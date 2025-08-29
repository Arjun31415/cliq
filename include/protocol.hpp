#include <algorithm>
#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <magic_enum/magic_enum.hpp>
#include <ostream>
#include <vector>
enum class MessageType : std::uint8_t {
  LoginReq = 0,
  LoginSuccess,
  LoginFail,

  ConnectionToClientReq,
  ConnectionToClientSuccess,
  ConnectionToClientFail,

  IncomingConnectionReq,
  AcceptIncomingConnectionReq,
  RejectIncomingConnectionReq,

  ChatMessage,

  ClientDisconnected,

};
struct MessageHeader {
  MessageType type;
  uint32_t message_length;
};
// Full message (header + payload)
struct Message {
  MessageHeader header;
  std::vector<std::uint8_t> payload;

  Message() = default;

  Message(MessageType t, const std::vector<std::uint8_t> &data)
      : payload(data) {
    header.type = t;
    header.message_length = htonl(static_cast<std::uint32_t>(payload.size()));
  }

  // Serialize into raw buffer
  std::vector<char> serialize() const {
    std::vector<char> buffer(sizeof(MessageHeader) + payload.size());

    buffer[0] = static_cast<std::uint8_t>(header.type);
    std::memcpy(buffer.data() + 1, &header.message_length,
                sizeof(header.message_length));
    if (!payload.empty()) {
      std::memcpy(buffer.data() + sizeof(MessageHeader), payload.data(),
                  payload.size());
    }
    return buffer;
  }

  // Deserialize from raw buffer
  static Message deserialize(const char *buffer, std::size_t totalSize) {
    Message msg;

    msg.header.type =
        static_cast<MessageType>(static_cast<std::uint8_t>(buffer[0]));

    std::uint32_t net_size;
    std::memcpy(&net_size, buffer + 1, sizeof(net_size));
    msg.header.message_length = net_size;

    std::uint32_t payload_size = ntohl(net_size);
    if (payload_size > 0 && totalSize >= sizeof(MessageHeader) + payload_size) {
      msg.payload.resize(payload_size);
      std::memcpy(msg.payload.data(), buffer + sizeof(MessageHeader),
                  payload_size);
    }

    return msg;
  }
};
// ------------------- ostream overloads -------------------

inline std::ostream &operator<<(std::ostream &os, MessageType type) {
  auto tmp = magic_enum::enum_name(type);
  os << tmp;
  return os;
}

inline std::ostream &operator<<(std::ostream &os, const MessageHeader &header) {
  os << "{ type=" << header.type << ", size=" << ntohl(header.message_length)
     << " }";
  return os;
}

inline std::ostream &operator<<(std::ostream &os, const Message &msg) {
  os << "Message " << msg.header;
  if (!msg.payload.empty()) {
    // Check if all bytes are printable
    bool printable =
        std::all_of(msg.payload.begin(), msg.payload.end(),
                    [](unsigned char c) { return std::isprint(c); });

    if (printable) {
      os << ", payload=\""
         << std::string(msg.payload.begin(), msg.payload.end()) << "\"";
    } else {
      os << ", payload=[";
      for (std::size_t i = 0; i < msg.payload.size(); i++) {
        if (i > 0)
          os << " ";
        os << std::hex << static_cast<int>(msg.payload[i]) << std::dec;
      }
      os << "]";
    }
  } else {
    os << ", payload=<empty>";
  }
  return os;
}
