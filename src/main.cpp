#include <arpa/inet.h>
#include <chrono>
#include <csignal>
#include <cstring>
#include <iostream>
#include <span>
#include <string_view>
#include <thread>

#include "IPv4Layer.h"
#include "IpAddress.h"
#include "Packet.h"
#include "PcapLiveDeviceList.h" // knows every network interface on machine
#include "TcpLayer.h"
#include "UdpLayer.h"

#include "parser.hpp"

namespace {

std::atomic<bool> g_running{true};

void handleSigint(int) { g_running = false; }

std::string_view toString(Transport t) {
  switch (t) {
  case Transport::TCP:
    return "TCP";
  case Transport::UDP:
    return "UDP";
  default:
    return "other";
  }
} // tostring

std::string ipToString(uint32_t ip) {
  return pcpp::IPv4Address(ip).toString();
} // ipToString

// NOTE: Temporary, check the parser's output
void printInfo(const PacketInfo &p) {
  std::cout << toString(p.transport) << "  " << ipToString(p.srcIp) << ':'
            << p.srcPort << " -> " << ipToString(p.dstIp) << ':' << p.dstPort
            << "  " << p.length << " B";
  if (p.stun)
    std::cout << "  [STUN]";
  if (p.rtp)
    std::cout << "  [RTP?]";
  if (p.sniHost)
    std::cout << "  SNI=" << *p.sniHost;
  for (const auto &[ip, name] : p.dnsAnswers)
    std::cout << "\n    DNS: " << name << " = " << ipToString(ip);
  std::cout << '\n';
} // printInfo

// struct for collecting packet stats
struct PacketStats {
  //
  int total = 0, nonIpv4 = 0;
  int tcp = 0, udp = 0, other = 0;
  int stun = 0, rtp = 0, sni = 0, dnsResponses = 0;

  void consume(const PacketInfo &p) {
    ++total;
    switch (p.transport) {
    case Transport::TCP:
      ++tcp;
      break;
    case Transport::UDP:
      ++udp;
      break;
    default:
      ++other;
      break;
    }
    if (p.stun)
      ++stun;
    if (p.rtp)
      ++rtp;
    if (p.sniHost)
      ++sni;
    if (!p.dnsAnswers.empty())
      ++dnsResponses;
  } // consume

  void print() const {
    std::cout << "IPv4 packets:      " << total << '\n'
              << "  TCP:             " << tcp << '\n'
              << "  UDP:             " << udp << '\n'
              << "  other:           " << other << '\n'
              << "  STUN:            " << stun << '\n'
              << "  RTP-looking:     " << rtp << '\n'
              << "  TLS SNI seen:    " << sni << '\n'
              << "  DNS responses:   " << dnsResponses << '\n'
              << "Skipped (non-IPv4): " << nonIpv4 << '\n';
  } // print

}; // packet struct

// capture thread tha truns once per packet
static void onPacketArrives(pcpp::RawPacket *raw,
                            pcpp::PcapLiveDevice * /*dev*/, void *cookie) {
  // extract cookie stat objects
  auto *stats = static_cast<PacketStats *>(cookie);

  auto info = parse(*raw);
  if (!info) {
    ++stats->nonIpv4;
    return;
  }

  // collect stats from packet
  stats->consume(*info);
  printInfo(*info);

} // onPacketArrives

// device helpers

void listInterfaces() {
  for (auto *dev :
       pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList()) {
    std::cout << "  " << dev->getName() << "  "
              << dev->getIPv4Address().toString() << '\n';
  }
} // listInterfaces

void printInterfaceInfo(const pcpp::PcapLiveDevice &dev) {
  std::cout << "Interface info:\n"
            << "    Name:            " << dev.getName() << '\n'
            << "    Description:     " << dev.getDesc() << '\n'
            << "    MAC address:     " << dev.getMacAddress().toString() << '\n'
            << "    Default gateway: " << dev.getDefaultGateway().toString()
            << '\n'
            << "    MTU:             " << dev.getMtu() << '\n';

  const auto &dns = dev.getDnsServers();
  if (!dns.empty()) {
    std::cout << "    DNS server:      " << dns.front().toString() << '\n';
  }
} // printInterfaceInfo

} // namespace

auto main(int argc, char *argv[]) -> int {
  if (argc < 2) {
    std::cout << "usage: nosy <interface>\n\nAvailable interfaces:\n";
    listInterfaces();
    return 1;
  }
  const std::string ifaceName = argv[1];

  // find interface by IP
  auto *dev =
      pcpp::PcapLiveDeviceList::getInstance().getDeviceByName(ifaceName);

  if (dev == nullptr) {
    std::cerr << "Cannot find interface '" << ifaceName << "'\n";
    return 1;
  }

  // getting info about interface
  printInterfaceInfo(*dev);

  // open device before capturing packets
  if (!dev->open()) {
    std::cerr << "Cannot open device" << std::endl;
    return 1;
  }

  std::signal(SIGINT, handleSigint);

  PacketStats stats;
  std::cout << "\nCapturing on" << ifaceName << " CTRL-C to stop\n\n";

  if (!dev->startCapture(onPacketArrives, &stats)) {
    std::cerr << "Failed to start capture\n";
    return 1;
  }

  while (g_running) {
    // sleep - packets are being captured async
    std::this_thread::sleep_for(std::chrono::seconds(100));
  }

  dev->stopCapture();
  dev->close();

  // print results
  std::cout << "Results:" << std::endl;
  stats.print();

  return 0;
}
