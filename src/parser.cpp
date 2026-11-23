#include "parser.hpp"
#include <algorithm>
#include <arpa/inet.h> // ntohl
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstring> // memcpy
#include <iostream>
#include <span>
#include <string_view>
#include <thread>

#include "DnsLayer.h"
#include "IPv4Layer.h"
#include "Packet.h"
#include "PcapLiveDeviceList.h" // knows every network interface on machine
#include "SSLHandshake.h"
#include "SSLLayer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"

// private helpers only visible locally
namespace {
// raw bytes after layer header
    std::span<const uint8_t> payloadOf(const pcpp::Layer &layer) {
        return {layer.getLayerPayload(), layer.getLayerPayloadSize()};
    } // payloadOf

// checks first two bites are 0, bytes 4-7 have magic cookie
bool isStun(std::span<const uint8_t> p) {
  if (p.size() < 20 || (p[0] & 0xC0) != 0) {
    return false;
  }
  uint32_t cookie;
  std::memcpy(&cookie, p.data() + 4, sizeof cookie);
  return ntohl(cookie) == 0x2112A442;
} // isStun

// checks RTP
bool isRtp(std::span<const uint8_t> p) {
  return p.size() >= 12 && (p[0] & 0xC0) == 0x80;
} // isRtp

// layer 4 protocol, ports, and STUN/RTP for UDP
void fillTransport(const pcpp::Packet &pkt, PacketInfo &info) {
  if (auto *tcp = pkt.getLayerOfType<pcpp::TcpLayer>()) {
    info.transport = Transport::TCP;
    info.srcPort = tcp->getSrcPort();
    info.dstPort = tcp->getDstPort();
  } else if (auto *udp = pkt.getLayerOfType<pcpp::UdpLayer>()) {
    info.transport = Transport::UDP;
    info.srcPort = udp->getSrcPort();
    info.dstPort = udp->getDstPort();
    auto payload = payloadOf(*udp);
    info.stun = isStun(payload);
    info.rtp = !info.stun && isRtp(payload);
  }
} // fillTransport

// Hostname from a TLS ClientHello, if applicable
std::optional<std::string> extractSni(const pcpp::Packet &pkt) {
  auto *hs = pkt.getLayerOfType<pcpp::SSLHandshakeLayer>();
  if (!hs)
    return std::nullopt;
  auto *hello = hs->getHandshakeMessageOfType<pcpp::SSLClientHelloMessage>();
  if (!hello)
    return std::nullopt;
  auto *sni =
      hello->getExtensionOfType<pcpp::SSLServerNameIndicationExtension>();
  if (!sni)
    return std::nullopt;
  return sni->getHostName();
} // extractSni

// IP and name pairs from a DNS response
void extractDnsAnswers(const pcpp::Packet &pkt, PacketInfo &info) {
  auto *dns = pkt.getLayerOfType<pcpp::DnsLayer>();
  if (!dns || dns->getDnsHeader()->queryOrResponse != 1)
    return; // responses only

  auto *query = dns->getFirstQuery();
  if (!query)
    return;
  const std::string name =
      query->getName(); // the name that was asked for, not the CNAME

  for (auto *a = dns->getFirstAnswer(); a != nullptr;
       a = dns->getNextAnswer(a)) {
    if (a->getDnsType() != pcpp::DNS_TYPE_A)
      continue; // IPv4 answers only
    auto ip = a->getData()->castAs<pcpp::IPv4DnsResourceData>()->getIpAddress();
    info.dnsAnswers.emplace_back(ip.toInt(), name);
  }
} // extractDnsAnswers

} // namespace
// public

std::optional<PacketInfo> parse(pcpp::RawPacket &raw) {
  pcpp::Packet pkt(&raw); // parses every layer; doesn't take ownership of raw

  auto *ip = pkt.getLayerOfType<pcpp::IPv4Layer>();
  if (!ip)
    return std::nullopt; // IPv6/ARP/etc.: skip for now

  PacketInfo info;
  info.srcIp = ip->getSrcIPv4Address().toInt();
  info.dstIp = ip->getDstIPv4Address().toInt();
  info.length = raw.getRawDataLen();

  fillTransport(pkt, info);
  info.sniHost = extractSni(pkt);
  extractDnsAnswers(pkt, info);

  return info;
} // parse
