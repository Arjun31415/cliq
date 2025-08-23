#include <CLI/CLI.hpp>
#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <iostream>
#include <memory>
#include <netinet/in.h>
#include <quill/Backend.h>
#include <quill/Frontend.h>
#include <quill/LogMacros.h>
#include <quill/Logger.h>
#include <quill/sinks/ConsoleSink.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// ------------------ Config ------------------
struct Config {
  std::string host{"127.0.0.1"};
  int port{5003};
  int buffer_size{512};
};

quill::Logger *g_logger = nullptr;
std::atomic<bool> g_terminate{false};

// ------------------ Signal Handler ------------------
void signal_handler(int signo) {
  LOG_DEBUG(g_logger, "Received Signal: {}", signo);
  if (signo == SIGINT || signo == SIGTERM) {
    g_terminate.store(true);
  }
}

// ------------------ IO Helpers ------------------
bool send_all(int fd, const void *data, size_t len) {
  const char *buf = static_cast<const char *>(data);
  size_t total_sent = 0;
  while (total_sent < len) {
    ssize_t sent = send(fd, buf + total_sent, len - total_sent, 0);
    if (sent < 0) {
      if (errno == EINTR)
        continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return false;
      LOG_ERROR(g_logger, "send() failed: {} (errno={})", strerror(errno),
                errno);
      return false;
    }
    total_sent += sent;
  }
  return true;
}

bool send_message(int fd, const std::string &msg) {
  return send_all(fd, msg.data(), msg.size());
}

bool recv_message(int fd, std::string &msg) {
  char buffer[512]; // A temporary buffer
  ssize_t bytes_read = recv(fd, buffer, sizeof(buffer), 0);

  if (bytes_read < 0) {
    LOG_ERROR(g_logger, "recv() failed: {}", strerror(errno));
    return false;
  }
  if (bytes_read == 0) {
    // This means the server closed the connection.
    return false;
  }

  // Assign the exact number of bytes read.
  msg.assign(buffer, bytes_read);
  return true;
}

// ------------------ Main ------------------
int main(int argc, char **argv) {
  std::signal(SIGINT, signal_handler);
  std::signal(SIGTERM, signal_handler);

  CLI::App app("Chat Client in C++");
  Config cfg;
  app.add_option("-p,--port", cfg.port, "Server port")
      ->check(CLI::Range(1024, 65535));
  app.add_option("--host", cfg.host, "Server hostname/IP");

  // Start logging
  quill::Backend::start();
  g_logger = quill::Frontend::create_or_get_logger(
      "client",
      quill::Frontend::create_or_get_sink<quill::ConsoleSink>(
          "sink_id_client", [] {
            quill::ConsoleSinkConfig cfg;
            cfg.set_colour_mode(quill::ConsoleSinkConfig::ColourMode::Always);
            return cfg;
          }()));

#ifdef DEBUG_BUILD
  g_logger->set_log_level(quill::LogLevel::Debug);
#else
  g_logger->set_log_level(quill::LogLevel::Info);
#endif

  CLI11_PARSE(app, argc, argv);

  // Create socket
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    LOG_ERROR(g_logger, "Failed to create socket: {} (errno={})",
              strerror(errno), errno);
    return 1;
  }

  sockaddr_in server_addr{};
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(cfg.port);

  if (inet_pton(AF_INET, cfg.host.c_str(), &server_addr.sin_addr) <= 0) {
    LOG_ERROR(g_logger, "Invalid address {}", cfg.host);
    close(sockfd);
    return 1;
  }

  if (connect(sockfd, (sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    LOG_ERROR(g_logger, "Failed to connect to {}:{} - {} (errno={})", cfg.host,
              cfg.port, strerror(errno), errno);
    close(sockfd);
    return 1;
  }

  LOG_INFO(g_logger, "Connected to {}:{}", cfg.host, cfg.port);

  // Client loop
  while (!g_terminate.load()) {
    std::cout << "Enter Message: ";
    std::string msg;
    std::getline(std::cin, msg);
    if (msg.empty())
      continue;

    if (!send_message(sockfd, msg)) {
      LOG_ERROR(g_logger, "Failed to send message, closing socket");
      break;
    }
    LOG_DEBUG(g_logger, "Sent message: {}", msg);

    std::string reply;
    if (!recv_message(sockfd, reply)) {
      LOG_ERROR(g_logger, "Server closed connection or recv failed");
      break;
    }
    std::cout << "Server says: " << reply << std::endl;
  }

  close(sockfd);
  LOG_INFO(g_logger, "Client shutdown complete");
  return 0;
}
