#include "rip.h"
#include <stdint.h>
#include <stdlib.h>

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(for response) and 0(for request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
  // TODO:

  uint16_t total_len = (packet[2] << 8) | (packet[3]);
  if (total_len > len) {
    return false;
  }
  uint8_t command = packet[28];
  uint8_t version = packet[29];
  uint8_t zero = packet[30] | packet[31];

  //output = new RipPacket();
  output->command = command;
  output->numEntries = (len - 31) / 20;

  for (uint32_t i = 0; i < output->numEntries; i++) {
    //uint32_t numEntries = (len - 31) / 20;
    uint16_t family = (packet[32 + i * 20] << 8) | (packet[33 + i * 20]);
    uint8_t tag = packet[34 + i * 20] | packet[35 + i * 20];
    if (!(((command == 2 && family == 2) || (command == 1 && family == 0)) && version == 2 && zero == 0 && tag == 0)) {
      return false;
    }
    uint32_t addr = (packet[36 + i * 20]) | (packet[37 + i * 20] << 8) | (packet[38 + i * 20] << 16) | (packet[39 + i * 20] << 24);
    uint32_t mask = (packet[40 + i * 20]) | (packet[41 + i * 20] << 8) | (packet[42 + i * 20] << 16) | (packet[43 + i * 20] << 24);
    uint32_t nexthop = (packet[44 + i * 20]) | (packet[45 + i * 20] << 8) | (packet[46 + i * 20] << 16) | (packet[47 + i * 20] << 24);
    uint32_t metric = (packet[48 + i * 20] << 24) | (packet[49 + i * 20] << 16) | (packet[50 + i * 20] << 8) | (packet[51 + i * 20]);
    uint32_t metric_small = (packet[51 + i * 20] << 24) | (packet[50 + i * 20] << 16) | (packet[49 + i * 20] << 8) | (packet[48 + i * 20]);
    if (metric_small < 1 || metric_small > 16) {
      return false;
    }
    bool flag = true;
    bool before = ((mask & 0x1) != 0);
    for (int i = 0; i < 32; i++) {
      uint32_t mask_mask = (0x00000001 << i);
      bool now = ((mask & mask_mask) != 0);
      if (now ^ before) {
        if (flag) {
          flag = false;
        }
        else {
          return false;
        }
      }
      before = now;
    }
    output->entries[i].addr = addr;
    output->entries[i].mask = mask;
    output->entries[i].nexthop = nexthop;
    output->entries[i].metric = metric;
  }

  return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  // TODO:
  uint32_t len = 4 + 20 * rip->numEntries;
  buffer[28] = rip->command;
  buffer[29] = 2;
  buffer[30] = 0;
  buffer[31] = 0;
  for (uint32_t i = 0; i < rip->numEntries; i++) {
    buffer[32 + i * 20] = 0;
    buffer[33 + i * 20] = (rip->command == 1) ? 0 : 2;
    buffer[34 + i * 20] = 0;
    buffer[35 + i * 20] = 0;
    buffer[36 + i * 20] = (rip->entries[i].addr & 0x000000FF);
    buffer[37 + i * 20] = ((rip->entries[i].addr >> 8) & 0x000000FF);
    buffer[38 + i * 20] = ((rip->entries[i].addr >> 16) & 0x000000FF);
    buffer[39 + i * 20] = ((rip->entries[i].addr >> 24) & 0x000000FF);
    buffer[40 + i * 20] = (rip->entries[i].mask & 0x000000FF);
    buffer[41 + i * 20] = ((rip->entries[i].mask >> 8) & 0x000000FF);
    buffer[42 + i * 20] = ((rip->entries[i].mask >> 16) & 0x000000FF);
    buffer[43 + i * 20] = ((rip->entries[i].mask >> 24) & 0x000000FF);
    buffer[44 + i * 20] = (rip->entries[i].nexthop & 0x000000FF);
    buffer[45 + i * 20] = ((rip->entries[i].nexthop >> 8) & 0x000000FF);
    buffer[46 + i * 20] = ((rip->entries[i].nexthop >> 16) & 0x000000FF);
    buffer[47 + i * 20] = ((rip->entries[i].nexthop >> 24) & 0x000000FF);
    buffer[48 + i * 20] = ((rip->entries[i].metric >> 24) & 0x000000FF);
    buffer[49 + i * 20] = ((rip->entries[i].metric >> 16) & 0x000000FF);
    buffer[50 + i * 20] = ((rip->entries[i].metric >> 8) & 0x000000FF);
    buffer[51 + i * 20] = ((rip->entries[i].metric) & 0x000000FF);
  }
  return len;
}


uint32_t assembleUDP(uint8_t *buffer, uint32_t riplen) {
  uint32_t port = 520;
  uint32_t len = riplen + 8;
  buffer[20] = ((port >> 8) & 0x000000FF);
  buffer[21] = (port & 0x000000FF);
  buffer[22] = ((port >> 8) & 0x000000FF);
  buffer[23] = (port & 0x000000FF);
  buffer[24] = ((len >> 8) & 0x000000FF);
  buffer[25] = (len & 0x000000FF);
  buffer[26] = 0x00;
  buffer[27] = 0x00;
  return len;
}

uint32_t assembleIP(uint8_t *buffer, uint32_t udplen, uint32_t src, uint32_t dst) {
  uint32_t len = udplen + 20;
  buffer[0] = ((4 << 4) + 5);
  buffer[1] = 0;
  buffer[2] = ((len >> 8) & 0x000000FF);
  buffer[3] = (len & 0x000000FF);
  buffer[4] = 0;
  buffer[5] = 0;
  buffer[6] = 0;
  buffer[7] = 0;
  buffer[8] = 1;
  buffer[9] = 17;
  buffer[10] = 0;
  buffer[11] = 0;
  buffer[12] = (src & 0x000000FF);
  buffer[13] = ((src >> 8) & 0x000000FF);
  buffer[14] = ((src >> 16) & 0x000000FF);
  buffer[15] = ((src >> 24) & 0x000000FF);
  buffer[16] = (dst & 0x000000FF);
  buffer[17] = ((dst >> 8) & 0x000000FF);
  buffer[18] = ((dst >> 16) & 0x000000FF);
  buffer[19] = ((dst >> 24) & 0x000000FF);

  int32_t sum = 0;
  for (uint8_t i = 0; i < (5 << 2); i += 2) {
    sum += (buffer[i] << 8) + (buffer[i + 1]);
    while((sum & 0xFFFF0000) != 0) {
      sum = ((sum >> 16) & 0x0000FFFF) + (sum & 0x0000FFFF);
    }
  }
  sum = ~sum;
  buffer[10] = ((sum >> 8) & 0x000000FF);
  buffer[11] = (sum & 0x000000FF);


  return len;
}