#include "protocol.hpp"
#include <CLI/CLI.hpp>
#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <iostream>
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

// bool send_message(int fd, const std::string &msg) {
//   return send_all(fd, msg.data(), msg.size());
// }
//
// bool recv_message(int fd, std::string &msg) {
//   char buffer[512]; // A temporary buffer
//   ssize_t bytes_read = recv(fd, buffer, sizeof(buffer), 0);
//
//   if (bytes_read < 0) {
//     LOG_ERROR(g_logger, "recv() failed: {}", strerror(errno));
//     return false;
//   }
//   if (bytes_read == 0) {
//     // This means the server closed the connection.
//     return false;
//   }
//
//   // Assign the exact number of bytes read.
//   msg.assign(buffer, bytes_read);
//   return true;
// }
//

bool send_message(int fd, const Message &msg) {
  auto raw = msg.serialize();
  return send_all(fd, raw.data(), raw.size());
}

bool recv_message(int fd, Message &msg) {
  char buffer[512]; // read raw data
  ssize_t bytes_read = recv(fd, buffer, sizeof(buffer), 0);

  if (bytes_read < 0) {
    LOG_ERROR(g_logger, "recv() failed: {}", strerror(errno));
    return false;
  }
  if (bytes_read == 0) {
    // Server closed connection.
    return false;
  }

  msg = Message::deserialize(buffer, bytes_read);
  return true;
}
// -1 -> quit (cant recover from error)
// 0 -> All ok login sucessfull
// 1 -> try again (input empty or something)
// 2 -> Login failed
int handle_login_helper(const int &sockfd) {

  std::cout << "Enter Username: ";
  std::string input;
  std::getline(std::cin, input);
  if (input.empty())
    return 1;
  Message msg(MessageType::LoginReq,
              std::vector<std::uint8_t>(input.begin(), input.end()));

  if (!send_message(sockfd, msg)) {
    LOG_ERROR(g_logger, "Failed to send message, closing socket");
    return -1;
  }
  LOG_DEBUG(
      g_logger, "Sent message: {}",
      static_cast<std::ostringstream &&>(std::ostringstream() << msg).str());

  Message reply;
  if (!recv_message(sockfd, reply)) {
    LOG_ERROR(g_logger, "Server closed connection or recv failed");
    return -1;
  }
  LOG_DEBUG(
      g_logger, "Server says: {}",
      static_cast<std::ostringstream &&>(std::ostringstream() << reply).str());
  if (reply.header.type == MessageType::LoginFail) {
    LOG_ERROR(g_logger, "Login failed: {} ",
              static_cast<std::ostringstream &&>(std::ostringstream() << reply)
                  .str());
    return 2;
  } else if (reply.header.type == MessageType::ConnectionToClientSuccess) {
    LOG_INFO(g_logger, "LOGIN sucessfull");
    return 0;
  } else {
    LOG_ERROR(g_logger, "Unexpected server reply: {}",
              static_cast<std::ostringstream &&>(std::ostringstream() << reply)
                  .str());
    return 3;
  }
}
int handle_login(const int &sockfd) {
  while (!g_terminate.load()) {
    int ok = handle_login_helper(sockfd);
    if (ok < 0)
      return ok;
    if (ok > 0)
      continue;
    else
      break;
  }
  return 0;
}
// -1 -> quit (network error)
// 0 -> All ok, connection successful
// 1 -> try again (input empty)
// 2 -> connection failed
int handle_connect_helper(const int &sockfd, std::string &username) {
  std::cout << "Enter username to connect: ";
  std::string target_username;
  std::getline(std::cin, target_username);

  if (target_username.empty()) {
    LOG_INFO(g_logger, "No username entered, aborting connection request");
    return 1;
  }

  Message msg(MessageType::ConnectionToClientReq,
              std::vector<std::uint8_t>(target_username.begin(),
                                        target_username.end()));

  if (!send_message(sockfd, msg)) {
    LOG_ERROR(g_logger, "Failed to send connection request, closing socket");
    return -1;
  }

  LOG_DEBUG(
      g_logger, "Sent connection request: {}",
      static_cast<std::ostringstream &&>(std::ostringstream() << msg).str());

  Message reply;
  if (!recv_message(sockfd, reply)) {
    LOG_ERROR(g_logger, "Server closed connection or recv failed");
    return -1;
  }

  LOG_DEBUG(
      g_logger, "Server replied: {}",
      static_cast<std::ostringstream &&>(std::ostringstream() << reply).str());

  if (reply.header.type == MessageType::ConnectionToClientFail) {
    LOG_ERROR(g_logger, "Connection failed: {}",
              static_cast<std::ostringstream &&>(std::ostringstream() << reply)
                  .str());
    return 2;
  } else if (reply.header.type == MessageType::ConnectionToClientSuccess) {
    LOG_INFO(g_logger, "Connection to {} successful", target_username);
    username = target_username;
    return 0;
  } else {
    LOG_ERROR(g_logger, "Unexpected server reply: {}",
              static_cast<std::ostringstream &&>(std::ostringstream() << reply)
                  .str());
    return 3;
  }
}

int handle_connect(const int &sockfd, std::string &connected_user) {

  while (!g_terminate.load()) {
    int ok = handle_connect_helper(sockfd, connected_user);
    if (ok < 0)
      return ok; // network error
    if (ok > 0)
      continue; // try again (empty input)
    else {
      return 0;
    }
  }
  return 0;
}
int handle_incoming_req(const int &sockfd, const Message &server_msg,
                        std::string &connected_user) {

  std::string from_user(server_msg.payload.begin(), server_msg.payload.end());
  LOG_INFO(g_logger, "Incoming connection request from {}", from_user);
  std::cout << "Incoming Chat request from " << from_user << std::endl;
  std::cout << "Accept (y/n): ?";
  char ch;
  std::cin >> ch;
  if (ch == 'y') {
    Message msg(MessageType::AcceptIncomingConnectionReq, server_msg.payload);
    if (!send_message(sockfd, msg)) {
      LOG_ERROR(g_logger, "Failed to send connection request, closing socket");
      return -1;
    }
  } else {
    Message msg(MessageType::RejectIncomingConnectionReq, server_msg.payload);
    if (!send_message(sockfd, msg)) {
      LOG_ERROR(g_logger, "Failed to send connection request, closing socket");
      return -1;
    }
    // no need to recv message from server here
    return 0;
  }
  Message reply;
  if (!recv_message(sockfd, reply)) {
    LOG_ERROR(g_logger, "Server closed connection or recv failed");
    return -1;
  }
  if (reply.header.type != MessageType::ConnectionToClientSuccess) {
    LOG_ERROR(g_logger, "Unexpected error while connecting to client: {}",
              static_cast<std::ostringstream &&>(std::ostringstream() << reply)
                  .str());
    return -1;
  }
  LOG_INFO(g_logger, "Connection successfull");
  connected_user = from_user;
  return 0;
}
void quit_client(const int &sockfd) {
  close(sockfd);
  LOG_INFO(g_logger, "Client shutdown complete");
  exit(1);
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
  if (handle_login(sockfd) != 0) {
    quit_client(sockfd);
  }
  std::string connected_user;
  int max_fd = std::max(STDIN_FILENO, sockfd);
  while (!g_terminate.load()) {
    // select() modifies the fd_set you pass to it. Specifically:
    // After select() returns, the fd_set will only have the file descriptors
    // that are ready.
    // Any descriptors that were not ready are cleared from the set.
    //
    // This means that after each call to select(), your fd_set is no longer the
    // original set of all fds you want to monitor.
    //
    // So if you reused the same fd_set without resetting it, the next select()
    // call would only check the fds that were ready the previous time —
    // potentially ignoring other fds.
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sockfd, &readfds);
    FD_SET(STDIN_FILENO, &readfds);

    // Timeout for select (optional, 0.1s)
    struct timeval tv{};
    tv.tv_sec = 0;
    tv.tv_usec = 100000;

    int ready = select(max_fd + 1, &readfds, nullptr, nullptr, &tv);

    if (ready < 0) {
      if (errno == EINTR)
        continue;
      LOG_ERROR(g_logger, "select() failed: {}", strerror(errno));
      break;
    }

    // --- 1. Incoming server messages ---
    if (FD_ISSET(sockfd, &readfds)) {
      Message server_msg;
      if (recv_message(sockfd, server_msg)) {
        switch (server_msg.header.type) {
        case MessageType::ClientDisconnected: {
          LOG_INFO(g_logger, "client: {} disconnected", connected_user);
          std::cout << "Your friend " << connected_user << " disconnected\n";
          connected_user.clear();
          break;
        }
        case MessageType::IncomingConnectionReq: {

          handle_incoming_req(sockfd, server_msg, connected_user);

          break;
        }
        case MessageType::ChatMessage: {
          std::string text(server_msg.payload.begin(),
                           server_msg.payload.end());
          LOG_INFO(g_logger, "Message from {}: {}", connected_user, text);
          break;
        }
        default:
          LOG_ERROR(g_logger, "Unexpected message: {}",
                    static_cast<std::ostringstream &&>(std::ostringstream()
                                                       << server_msg)
                        .str());
        }
      } else {
        LOG_ERROR(g_logger, "Server disconnected");
        break;
      }
    }

    // --- 2. User input ---
    if (FD_ISSET(STDIN_FILENO, &readfds)) {
      LOG_DEBUG(g_logger, "getting user input");
      std::string input;
      std::getline(std::cin, input);

      if (connected_user.empty()) {
        // Not connected yet → attempt connection if input is not empty
        if (!input.empty()) {
          std::string tmp_user;
          int ok = handle_connect_helper(sockfd, tmp_user);
          if (ok == 0)
            connected_user = tmp_user;
          if (ok < 0)
            break; // network error
        } else {
          // Empty input → just wait
        }
      } else {
        std::cout << "Enter message to send: ";
        // Connected → send chat message
        if (!input.empty()) {
          Message chat_msg(
              MessageType::ChatMessage,
              std::vector<std::uint8_t>(input.begin(), input.end()));
          if (!send_message(sockfd, chat_msg)) {
            LOG_ERROR(g_logger, "Failed to send chat message, closing socket");
            break;
          }
          LOG_DEBUG(g_logger, "Sent chat message: {}",
                    static_cast<std::ostringstream &&>(std::ostringstream()
                                                       << chat_msg)
                        .str());
        }
      }
    }
  }

  return 0;
}
