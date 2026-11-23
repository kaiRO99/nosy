#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
#include <string_view>
#include <thread>

#include "IPv4Layer.h"
#include "Packet.h"
#include "PcapLiveDeviceList.h" // knows every network interface on machine
#include "TcpLayer.h"
#include "UdpLayer.h"

auto main(int argc, char *argv[]) -> int {
  // IPv4 address of interface
  std::string interfaceIPAddr = "10.0.0.1";

  // find interface by IP
  auto *dev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByName("wlan0");

  if (dev == nullptr) {
    std::cerr << "Cannot find interface with IPv4 address of '"
              << interfaceIPAddr << "'" << std::endl;
    return 1;
  }

  // getting info about interface

  std::cout << "Interface info:" << std::endl
            << "    Interface name:        " << dev->getName()
            << std::endl // get interface name
            << "    Interface description: " << dev->getDesc()
            << std::endl // get interface name
            << "    MAC address:           " << dev->getMacAddress()
            << std::endl // get interface MAC address
            << "    Default gateway:       " << dev->getDefaultGateway()
            << std::endl // get default gateway
            << "    Interface MTU:         " << dev->getMtu()
            << std::endl; // get interface MTU

  if (!dev->getDnsServers().empty()) {
    std::cout << "    DNS server:            " << dev->getDnsServers().front()
              << std::endl;
  }

  return 0;
}
