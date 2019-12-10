#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>


typedef uint32_t in_addr_t;

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index, uint32_t *metric);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);
extern void get_packet(RipPacket * res);
extern uint32_t assembleUDP(uint8_t *buffer, uint32_t riplen);
extern uint32_t assembleIP(uint8_t *buffer, uint32_t udplen, uint32_t src, uint32_t dst);

uint32_t mask_len(uint32_t mask) {
  for (int i = 0; i < 32; i++){
    if (mask & (1 << i) == 0){
      return i + 1;
    }
  }
  return 32;
}

char ip_buffer[20];
std::string ip_string(uint32_t addr){
  sprintf(ip_buffer, "%d.%d.%d.%d", addr & 0x000000FF, (addr >> 8) & 0x000000FF, (addr >> 16) & 0x000000FF, (addr >> 24) & 0x000000FF);
  return (std::string)ip_buffer;
}

char mac_buffer[20];
std::string mac_string(macaddr_t mac){
  sprintf(mac_buffer, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return std::string(mac_buffer);
}

uint8_t packet[2048];
uint8_t output[2048];
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0100000a, 0x0101000a, 0x0102000a,
                                     0x0103000a};


in_addr_t multicast_addr = (9 << 24) + 224;

int main(int argc, char *argv[]) {
  // 0a.
  int res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }

  // 0b. Add direct routes
  // For example:
  // 10.0.0.0/24 if 0
  // 10.0.1.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
    RoutingTableEntry entry = {
        .addr = addrs[i] & 0x00FFFFFF, // big endian
        .len = 24,        // small endian
        .if_index = i,    // small endian
        .nexthop = 0,      // big endian, means direct
        .metric = 1
    };
    update(true, entry);
  }



  uint64_t last_time = 0;
  uint64_t last_update_time = 0;
  while (1) {
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 5 * 1000) {
      // What to do?
      // send complete routing table to every interface
      // ref. RFC2453 3.8
      // multicast MAC for 224.0.0.9 is 01:00:5e:00:00:09
      RipPacket rip;
      get_packet(&rip);
      uint32_t riplen = assemble(&rip, output);
      uint32_t udplen = assembleUDP(output, riplen);
      for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
        uint32_t iplen  = assembleIP(output, udplen, addrs[i], multicast_addr);   
        macaddr_t multicast_mac;
        HAL_ArpGetMacAddress(i, multicast_addr, multicast_mac);
        HAL_SendIPPacket(i, output, iplen, multicast_mac);
        printf("Timer send packet from %08x(%s) to %08x(%s), port %d, len is %d, dst mac is %s.\n", addrs[i], ip_string(addrs[i]).c_str(), multicast_addr, ip_string(multicast_addr).c_str(), i, iplen, mac_string(multicast_mac).c_str());
      }   
      
      printf("30s Timer\n");
      last_time = time;
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac,
                              1000, &if_index);
    //printf("packet\n", packet);
    if (res == HAL_ERR_EOF) {
      break;
    } else if (res < 0) {
      return res;
    } else if (res == 0) {
      // Timeout
      continue;
    } else if (res > sizeof(packet)) {
      // packet is truncated, ignore it
      continue;
    }

    // 1. validate
    if (!validateIPChecksum(packet, res)) {
      printf("Invalid IP Checksum\n");
      continue;
    }
    in_addr_t src_addr, dst_addr;
    // extract src_addr and dst_addr from packet
    // big endian
    src_addr = (packet[12]) | (packet[13] << 8) | (packet[14] << 16) | (packet[15] << 24);
    dst_addr = (packet[16]) | (packet[17] << 8) | (packet[18] << 16) | (packet[19] << 24);




    // 2. check whether dst is me
    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
    }
    // TODO: Handle rip multicast address(224.0.0.9)?
    if (memcmp(&dst_addr, &multicast_addr, sizeof(in_addr_t)) == 0){
      dst_is_me = true;
    }

    printf("Rev packet from %08x(%s)(mac %s) to %08x(%s)(mac %s), port %d, len is %d, res is %d, dst is%sme\n", src_addr, ip_string(src_addr).c_str(), mac_string(src_mac).c_str(), dst_addr, ip_string(dst_addr).c_str(), mac_string(dst_mac).c_str(), if_index, sizeof(packet), res, dst_is_me?" ":" not ");



    if (dst_is_me) {
      // 3a.1
      RipPacket rip;
      // check and validate
      if (disassemble(packet, res, &rip)) {
        if (rip.command == 1) {
          // 3a.3 request, ref. RFC2453 3.9.1
          // only need to respond to whole table requests in the lab
          RipPacket resp;
          // TODO: fill resp
          get_packet(&resp);
          // assemble
          // IP
          //output[0] = 0x45;
          // ...
          // UDP
          // port = 520
          //output[20] = 0x02;
          //output[21] = 0x08;
          // ...
          // RIP
          uint32_t riplen = assemble(&resp, output);
          uint32_t udplen = assembleUDP(output, riplen);
          uint32_t iplen  = assembleIP(output, udplen, addrs[if_index], src_addr);
          // checksum calculation for ip and udp
          // if you don't want to calculate udp checksum, set it to zero
          // send it back
          HAL_SendIPPacket(if_index, output, iplen, src_mac);
          printf("Response send packet from %08x(%s) to %08x(%s), port %d, len is %d, dst mac is %s.\n", addrs[if_index], ip_string(addrs[if_index]).c_str(), src_addr, ip_string(src_addr).c_str(), if_index, iplen, mac_string(src_mac).c_str());
        } else {
          // 3a.2 response, ref. RFC2453 3.9.2
          // update routing table
          // new metric = ?
          // update metric, if_index, nexthop
          // what is missing from RoutingTableEntry?
          // TODO: use query and update
          // triggered updates? ref. RFC2453 3.10.1
          bool trigger_flag = false;
          for (uint32_t i = 0; i < rip.numEntries; i++) {
            if (rip.entries[i].metric < 15) {
              uint32_t nexthop, dest_if, metric;
              RoutingTableEntry new_entry = {
                .addr = rip.entries[i].addr,
                .len = mask_len(rip.entries[i].mask),
                .if_index = if_index,
                .nexthop = src_addr,
                .metric = rip.entries[i].metric + 1
              };
              if (query(rip.entries[i].addr, &nexthop, &dest_if, &metric)){
                if (nexthop == src_addr && rip.entries[i].metric + 1 != metric){
                  update(true, new_entry);
                  trigger_flag = true;
                }
                else if(rip.entries[i].metric + 1 < metric) {
                  update(true, new_entry);
                  trigger_flag = true;
                }
              }
              else {
                update(true, new_entry);
                trigger_flag = true;
              }
            }
          }
          if (trigger_flag && time > last_update_time + 2 * 1000) {
            last_update_time = time;
            trigger_flag = false;
            for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
              if (i != if_index){
                RipPacket resp;
                get_packet(&resp);
                uint32_t riplen = assemble(&resp, output);
                uint32_t udplen = assembleUDP(output, riplen);
                uint32_t iplen  = assembleIP(output, udplen, addrs[if_index], src_addr);
                HAL_SendIPPacket(if_index, output, iplen, src_mac);
                printf("Update send packet from %08x(%s) to %08x(%s), port %d, len is %d, dst mac is %s.\n", addrs[if_index], ip_string(addrs[if_index]).c_str(), src_addr, ip_string(src_addr).c_str(), if_index, iplen, mac_string(src_mac).c_str());
              }
            }
          }
          
        }
      }
    } else {
      // 3b.1 dst is not me
      // forward
      // beware of endianness
      uint32_t nexthop, dest_if, metric;
      if (query(dst_addr, &nexthop, &dest_if, &metric)) {
        // found
        macaddr_t dest_mac;
        // direct routing
        if (nexthop == 0) {
          nexthop = dst_addr;
        }
        if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
          // found
          memcpy(output, packet, res);

          if(output[8] == 0){
            printf("ttl = 0\n");
            continue;
          }
          // update ttl and checksum
          forward(output, res);
          // TODO: you might want to check ttl=0 case
          HAL_SendIPPacket(dest_if, output, res, dest_mac);
          printf("Send packet from %08x(%s) to %08x(%s), port %d, len is %d, dst mac is %s.\n", addrs[dest_if], ip_string(addrs[dest_if]).c_str(), dst_addr, ip_string(dst_addr).c_str(), dest_if, sizeof(packet), mac_string(dest_mac).c_str());
        } else {
          // not found
          // you can drop it
          printf("ARP not found for %x\n", nexthop);
        }
      } else {
        // not found
        // optionally you can send ICMP Host Unreachable
        printf("IP not found for %x\n", src_addr);
      }
    }
  }
  //printf("%s", output);
  return 0;
}
