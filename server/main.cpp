#include "protocol.hpp"
#include <CLI/CLI.hpp>
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <quill/Backend.h>
#include <quill/Frontend.h>
#include <quill/LogMacros.h>
#include <quill/Logger.h>
#include <quill/sinks/ConsoleSink.h>
#include <string>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

struct Config {
  std::string host{"127.0.0.1"};
  int port{5003};
  static const int buffer_size{512};
  static const int max_events{64};
} cfg;
quill::Logger *g_logger = nullptr; // global logger
std::atomic<bool> g_terminate{false};

struct ClientInfo {
  int fd;
  std::string username;
  int connected_fd{-1}; // -1 if not connected. fd of the other user it is
                        // connected to, to chat with.
  std::vector<char> buffer;
};
std::unordered_map<int, ClientInfo> clients;       // fd : info
std::unordered_map<std::string, int> username_map; // username : fd

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
// ---- IO helpers ----
bool send_all(int fd, const void *data, size_t len) {
  const char *buf = static_cast<const char *>(data);
  size_t total_sent = 0;
  while (total_sent < len) {
    ssize_t sent = send(fd, buf + total_sent, len - total_sent, 0);
    if (sent < 0) {
      if (errno == EINTR)
        continue; // retry
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return false; // try later
      LOG_ERROR(g_logger, "send() failed: {} (errno={})", strerror(errno),
                errno);
      return false;
    }
    total_sent += sent;
  }
  return true;
}

bool send_message(int fd, const std::string &msg) {
  if (!send_all(fd, msg.data(), msg.size()))
    return false;
  return true;
}

bool send_message(int fd, const std::vector<char> &msg) {
  if (!send_all(fd, msg.data(), msg.size()))
    return false;
  return true;
}
bool send_message(int fd, const Message &msg) {
  auto raw_msg = msg.serialize();
  return send_message(fd, raw_msg);
}

int setup(int argc, char **argv) {
  std::signal(SIGINT, signal_handler);
  std::signal(SIGTERM, signal_handler);
  CLI::App app("Chat webserver in c++");
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

  return 0;
}
void process_message(ClientInfo &client, const Message &msg) {
  auto convert_to_vec = [](const std::string &&str) {
    return std::vector<std::uint8_t>(str.begin(), str.end());
  };
  switch (msg.header.type) {
  case MessageType::LoginReq: {
    std::string username(msg.payload.begin(), msg.payload.end());
    if (username.empty() || username_map.count(username)) {
      Message reply(MessageType::LoginFail, {});
      send_message(client.fd, reply);
    } else {
      client.username = username;
      username_map[username] = client.fd;
      Message reply(MessageType::ConnectionToClientSuccess, {});
      send_message(client.fd, reply);
    }
    break;
  }

  case MessageType::ConnectionToClientReq: {
    std::string target(msg.payload.begin(), msg.payload.end());
    auto it = username_map.find(target);
    if (it == username_map.end()) {
      Message reply(MessageType::ConnectionToClientFail,
                    convert_to_vec("Username not found"));
      send_message(client.fd, reply);
    } else {
      int target_fd = it->second;
      // client.connected_fd = target_fd;
      // Message reply(MessageType::ConnectionToClientSuccess, {});
      // send_message(client.fd, reply);

      // Notify target user of incoming connection
      Message notify(
          MessageType::IncomingConnectionReq,
          std::vector<uint8_t>(client.username.begin(), client.username.end()));
      send_message(target_fd, notify);
    }
    break;
  }
  case MessageType::AcceptIncomingConnectionReq: {

    std::string target(msg.payload.begin(), msg.payload.end());
    auto it = username_map.find(target);
    if (it == username_map.end()) {
      // client disconnected
      Message reply(
          MessageType::ConnectionToClientFail,
          convert_to_vec("target client: " + target + " disconnected"));
      send_message(client.fd, reply);
    } else {
      int target_fd = it->second;
      client.connected_fd = target_fd;
      clients[target_fd].connected_fd = client.fd;

      Message reply(MessageType::ConnectionToClientSuccess, {});
      send_message(target_fd, reply);
      send_message(client.fd, reply);
    }
    break;
  }

  case MessageType::RejectIncomingConnectionReq: {

    std::string target(msg.payload.begin(), msg.payload.end());
    auto it = username_map.find(target);
    if (it == username_map.end()) {
      // target client disconnected
      // do nothing as sender client does not expect a reply
    } else {
      int target_fd = it->second;

      Message reply(MessageType::ConnectionToClientFail,
                    convert_to_vec(clients[client.fd].username +
                                   " does not want to connect."));
      send_message(target_fd, reply);
    }
    break;
  }

  case MessageType::ChatMessage: {
    if (client.connected_fd == -1) {
      LOG_ERROR(g_logger, "Client {} tried to send chat without connection",
                client.username);
      break;
    }
    auto &payload = msg.payload;
    LOG_DEBUG(
        g_logger, "Message: {}",
        static_cast<std::ostringstream &&>(std::ostringstream() << msg).str());
    send_message(client.connected_fd, msg); // forward to connected client
    break;
  }

  default:
    LOG_ERROR(
        g_logger, "Unknown message type from {}: {}", client.username,
        static_cast<std::ostringstream &&>(std::ostringstream() << msg).str());
  }
}
void remove_client(int fd) {
  auto it = clients.find(fd);
  if (it != clients.end()) {
    LOG_DEBUG(g_logger, "Client disconnected: {}", it->second.username);
    if (!it->second.username.empty()) {
      int other = it->second.connected_fd;
      if (other != -1) {
        Message reply(MessageType::ClientDisconnected, {});
        send_message(other, reply);
        clients.at(other).connected_fd = -1;
      }
      username_map.erase(it->second.username);
    }
    clients.erase(it);
  }
  close(fd);
}
void handle_new_connection(const int &server_fd, const int &epfd) {

  // Accept all incoming connections (Edge Triggered(ET) means must loop)
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
        LOG_ERROR(g_logger, "Error during accept connection: {} (errno={})",
                  strerror(errno), errno);
        break;
      }
    }

    make_socket_nonblocking(client_fd);

    struct epoll_event client_ev{};
    client_ev.events = EPOLLIN | EPOLLET; // edge-triggered read
    client_ev.data.fd = client_fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, client_fd, &client_ev) == -1) {
      LOG_ERROR(g_logger, "Error during epoll_ctl: client_fd : {} (errno={})",
                strerror(errno), errno);
      close(client_fd);
      continue;
    }

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    LOG_INFO(g_logger, "Accepted connection from {}:{} (fd={})", client_ip,
             ntohs(client_addr.sin_port), server_fd);
  }
}
void handle_client_data(const int &fd) {
  // Handle client data (ET → must read until EAGAIN)
  auto it = clients.find(fd);
  if (it == clients.end()) {
    // First time seeing this client
    clients[fd] = ClientInfo{fd};
    it = clients.find(fd);
  }
  ClientInfo &client = it->second;

  char buffer[cfg.buffer_size];

  while (true) {
    ssize_t bytes_read = recv(fd, buffer, sizeof(buffer), 0);
    if (bytes_read < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break; // no more data for ET
      } else {
        LOG_ERROR(g_logger, "recv failed for fd {}: {}", fd, strerror(errno));
        remove_client(fd);
        break;
      }
    } else if (bytes_read == 0) {
      LOG_INFO(g_logger, "Client (fd = {}) disconnected", fd);
      remove_client(fd);
      break;
    }

    // Append new data to client's leftover buffer
    client.buffer.insert(client.buffer.end(), buffer, buffer + bytes_read);

    // Deserialize full message
    Message msg =
        Message::deserialize(client.buffer.data(), client.buffer.size());
    LOG_DEBUG(
        g_logger, "Deserialized message from fd {}: {}", fd,
        static_cast<std::ostringstream &&>(std::ostringstream() << msg).str());

    // Handle message
    process_message(client, msg);

    // Remove processed bytes
    client.buffer.erase(client.buffer.begin(),
                        client.buffer.begin() + client.buffer.size());
  }
}

void handle_events(const int &n, epoll_event *events, const int &server_fd,
                   const int &epfd) {

  for (int i = 0; i < n; i++) {
    int fd = events[i].data.fd;
    LOG_DEBUG(g_logger, "event fd:{} server fd:{}", fd, server_fd);
    if (fd == server_fd) {
      // new connection
      handle_new_connection(server_fd, epfd);
    } else {
      handle_client_data(fd);
    }
  }
}

int main(int argc, char **argv) {
  if (setup(argc, argv)) {
    LOG_ERROR(g_logger, "Error during setup");
  }

  // ----------------- CREATE TCP SERVER ------------------------------
  //
  // 1. create server socket
  // socket() returns fd (>=0) on success which is the file descrptor of the
  // listening socket. internally kernel keeps a socket object, we just hold
  // the file descriptor
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
  // address/port that is in a TIME_WAIT state. Normally, if you close a
  // server and restart it immediately, bind() might fail with bind: Address
  // already in use because the port is stuck in TIME_WAIT. SO_REUSEADDR does
  // not allow two processes to bind to the exact same port at the same time
  // (unless combined with SO_REUSEPORT)
  //
  // SO_REUSEPORT - Allows multiple sockets (possibly in different processes
  // or threads) to bind to the same IP+port. The kernel will load-balance
  // incoming connections across them. Useful for multi-threaded servers (e.g.
  // nginx workers).
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
  epoll_event ev{}, events[cfg.max_events];
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
    int n = epoll_wait(epfd, events, cfg.max_events, -1);
    LOG_DEBUG(g_logger, "num events: {}", n);
    if (n == -1) {
      if (errno == EINTR)
        continue; // interrupted by signal, retry
      LOG_ERROR(g_logger, "Error during epoll wait: {} (errno={})",
                strerror(errno), errno);
      break; // need to cleanup
    }
    handle_events(n, events, server_fd, epfd);
  }

  LOG_DEBUG(g_logger, "Shutting down server gracefully");
  close(server_fd);
  close(epfd);
  return 0;
}
