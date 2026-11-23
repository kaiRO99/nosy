#ifndef PARSER_H_
#define PARSER_H_

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace pcpp {
    class RawPacket;
} // namespace pcpp

enum class Transport { TCP, UDP, Other };

struct PacketInfo {
    uint32_t srcIp = 0, dstIp = 0; // network byte order (IPv4Address::toInt())
    uint16_t srcPort = 0, dstPort = 0;
    Transport transport = Transport::Other;
    size_t length = 0;
    bool stun = false, rtp = false;
    std::optional<std::string> sniHost;
    std::vector<std::pair<uint32_t, std::string>> dnsAnswers; // IP → hostname
};

// Parse one captured packet. Returns nullopt for anything that isn't IPv4.
std::optional<PacketInfo> parse(pcpp::RawPacket &raw);

#endif // PARSER_H_
