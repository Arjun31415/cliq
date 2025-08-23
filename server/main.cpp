#include <CLI/CLI.hpp>
#include <arpa/inet.h>
#include <cerrno>
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
#include <string_view>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

struct Config {
  std::string host{"127.0.0.1"};
  int port{5003};
  int buffer_size{1024};
};
quill::Logger *g_logger = nullptr; // global logger
std::atomic<bool> g_terminate{false};

// Signal handler
void signal_handler(int signo) {
  LOG_DEBUG(g_logger, "Recieved Signal: {}", signo);
  if (signo == SIGINT || signo == SIGTERM) {
    g_terminate.store(true);
  }
}
// Utility: set a file descriptor to non-blocking mode
int make_socket_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1) {
    LOG_ERROR(g_logger, "fcntl get failed: {} (errno={})", strerror(errno),
              errno);
    return -1;
  }

  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
    LOG_ERROR(g_logger, "fcntl set failed: {} (errno={})", strerror(errno),
              errno);
    return -1;
  }
  return 0;
}
int main(int argc, char **argv) {
  std::signal(SIGINT, signal_handler);
  std::signal(SIGTERM, signal_handler);
  CLI::App app("Chat webserver in c++");
  Config cfg;
  app.add_option("-p,--port", cfg.port,
                 "Port to listen to for incoming requests")
      ->check(CLI::Range(1024, 65535));
  app.add_option("--host", cfg.host, "Server hostname/IP");

  // Logging init
  quill::Backend::start();

  g_logger = quill::Frontend::create_or_get_logger(
      "root",
      quill::Frontend::create_or_get_sink<quill::ConsoleSink>("sink_id_1", [] {
        quill::ConsoleSinkConfig cfg;
        cfg.set_colour_mode(quill::ConsoleSinkConfig::ColourMode::Always);
        return cfg;
      }()));
#ifdef DEBUG_BUILD
  g_logger->set_log_level(quill::LogLevel::Debug); // Release build
#else
  g_logger->set_log_level(quill::LogLevel::Info); // Debug build
#endif
  CLI11_PARSE(app, argc, argv);
  // std::cout << "Starting server on " << cfg.host << ":" << cfg.port << "\n";

  // ----------------- CREATE TCP SERVER ------------------------------
  //
  // 1. create server socket
  // socket() returns fd (>=0) on success which is the file descrptor of the
  // listening socket. internally kernel keeps a socket object, we just hold the
  // file descriptor
  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
    LOG_ERROR(g_logger, "Failed to create socket: {} (errno={})",
              strerror(errno), errno);
    return 1;
  }

  int opt = 1;
  // SOL_SOCKET is a socket option level
  //
  // SO_REUSEADDR is the option which controls whether you can reuse a local
  // address/port that is in a TIME_WAIT state. Normally, if you close a server
  // and restart it immediately, bind() might fail with bind: Address already in
  // use because the port is stuck in TIME_WAIT.
  // SO_REUSEADDR does not allow two processes to bind to the exact same port at
  // the same time (unless combined with SO_REUSEPORT)
  //
  // SO_REUSEPORT - Allows multiple sockets (possibly in different processes or
  // threads) to bind to the same IP+port. The kernel will load-balance incoming
  // connections across them. Useful for multi-threaded servers (e.g. nginx
  // workers).
  //
  // SO_KEEPALIVE - Enables TCP keepalive packets to detect dead peers.
  //
  // SO_RCVBUF / SO_SNDBUF - Control receive/send buffer sizes.
  //
  //
  // opt = 1 → enable the option.
  // opt = 0 → disable it.
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  // host address
  sockaddr_in addr{};
  addr.sin_family = AF_INET; // IPv4
  // host to network short
  addr.sin_port = htons(cfg.port);
  // convert string -> binary
  inet_pton(AF_INET, cfg.host.c_str(), &addr.sin_addr);
  if (bind(server_fd, (sockaddr *)&addr, sizeof(addr)) < 0) {
    LOG_ERROR(g_logger, "failed to bind: {} (errno={})", strerror(errno),
              errno);
    return 1;
  }
  if (listen(server_fd, SOMAXCONN) < 0) {
    LOG_ERROR(g_logger, "failed to listen: {} (errno={})", strerror(errno),
              errno);
    return 1;
  }
  make_socket_nonblocking(server_fd);

  // 2. Create an Epoll Instance
  int epfd = epoll_create1(0);
  if (epfd < 0) {

    LOG_ERROR(g_logger, "failed to create epoll fd: {} (errno={})",
              strerror(errno), errno);
    return 1;
  }
  const int max_events = 64;
  epoll_event ev{}, events[max_events];
  ev.events = EPOLLIN | EPOLLET; // ready for read (edge triggered)
  ev.data.fd = server_fd;
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, server_fd, &ev) == -1) {
    LOG_ERROR(g_logger, "epoll_ctl: listen_sock failed: {} (errno={})",
              strerror(errno), errno);
    return 1;
  }
  LOG_INFO(g_logger, "Starting server... Press Ctrl+C to exit");
  LOG_INFO(g_logger, "server listening on {}:{}", cfg.host, cfg.port);

  // 3. EVENT LOOP:
  while (!g_terminate.load()) {
    int n = epoll_wait(epfd, events, max_events, -1);
    LOG_DEBUG(g_logger, "num events: {}", n);
    if (n == -1) {
      if (errno == EINTR)
        continue; // interrupted by signal, retry
      LOG_ERROR(g_logger, "Error during epoll wait: {} (errno={})",
                strerror(errno), errno);
      break; // need to cleanup
    }

    for (int i = 0; i < n; i++) {
      int fd = events[i].data.fd;
      LOG_DEBUG(g_logger, "event fd:{} server fd:{}", fd, server_fd);
      if (fd == server_fd) {
        // new connection
        // Accept all incoming connections (ET means must loop)
        while (true) {
          struct sockaddr_in client_addr{};
          socklen_t client_len = sizeof(client_addr);
          int client_fd =
              accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
          if (client_fd == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
              // No more clients to accept
              break;
            } else {
              LOG_ERROR(g_logger,
                        "Error during accept connection: {} (errno={})",
                        strerror(errno), errno);
              break;
            }
          }

          make_socket_nonblocking(client_fd);

          struct epoll_event client_ev{};
          client_ev.events = EPOLLIN | EPOLLET; // edge-triggered read
          client_ev.data.fd = client_fd;
          if (epoll_ctl(epfd, EPOLL_CTL_ADD, client_fd, &client_ev) == -1) {
            LOG_ERROR(g_logger,
                      "Error during epoll_ctl: client_fd : {} (errno={})",
                      strerror(errno), errno);
            close(client_fd);
            continue;
          }

          char client_ip[INET_ADDRSTRLEN];
          inet_ntop(AF_INET, &client_addr.sin_addr, client_ip,
                    sizeof(client_ip));
          LOG_INFO(g_logger, "Accepted connection from {}:{} (fd={})",
                   client_ip, ntohs(client_addr.sin_port), fd);
        }
      } else {
        // Handle client data (ET → must read until EAGAIN)
        while (true) {
          char buf[512];
          ssize_t count = recv(fd, buf, sizeof(buf), 0);
          if (count > 0) {
            // Echo back
            send(fd, buf, count, 0);
          } else if (count == 0) {
            // Client disconnected
            LOG_INFO(g_logger, "Client (fd = {}) disconnected\n", fd);
            close(fd);
            break;
          } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
              // No more data now
              break;
            } else {
              perror("recv");
              LOG_ERROR(g_logger, "Failed during data recieve: {} (errno={})",
                        strerror(errno), errno);
              close(fd);
              break;
            }
          }
        }
      }
    }
  }

  LOG_DEBUG(g_logger, "Shutting down server gracefully");
  close(server_fd);
  close(epfd);
  return 0;
}
