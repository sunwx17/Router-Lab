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
    uint32_t metric = (packet[48 + i * 20]) | (packet[49 + i * 20] << 8) | (packet[50 + i * 20] << 16) | (packet[51 + i * 20] << 24);
    uint32_t metric_small = (packet[51 + i * 20]) | (packet[50 + i * 20] << 8) | (packet[49 + i * 20] << 16) | (packet[48 + i * 20] << 24);
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
  buffer[0] = rip->command;
  buffer[1] = 2;
  buffer[2] = 0;
  buffer[3] = 0;
  for (uint32_t i = 0; i < rip->numEntries; i++) {
    buffer[4 + i * 20] = 0;
    buffer[5 + i * 20] = (rip->command == 1) ? 0 : 2;
    buffer[6 + i * 20] = 0;
    buffer[7 + i * 20] = 0;
    buffer[8 + i * 20] = (rip->entries[i].addr & 0x000000FF);
    buffer[9 + i * 20] = ((rip->entries[i].addr >> 8) & 0x000000FF);
    buffer[10 + i * 20] = ((rip->entries[i].addr >> 16) & 0x000000FF);
    buffer[11 + i * 20] = ((rip->entries[i].addr >> 24) & 0x000000FF);
    buffer[12 + i * 20] = (rip->entries[i].mask & 0x000000FF);
    buffer[13 + i * 20] = ((rip->entries[i].mask >> 8) & 0x000000FF);
    buffer[14 + i * 20] = ((rip->entries[i].mask >> 16) & 0x000000FF);
    buffer[15 + i * 20] = ((rip->entries[i].mask >> 24) & 0x000000FF);
    buffer[16 + i * 20] = (rip->entries[i].nexthop & 0x000000FF);
    buffer[17 + i * 20] = ((rip->entries[i].nexthop >> 8) & 0x000000FF);
    buffer[18 + i * 20] = ((rip->entries[i].nexthop >> 16) & 0x000000FF);
    buffer[19 + i * 20] = ((rip->entries[i].nexthop >> 24) & 0x000000FF);
    buffer[20 + i * 20] = (rip->entries[i].metric & 0x000000FF);
    buffer[21 + i * 20] = ((rip->entries[i].metric >> 8) & 0x000000FF);
    buffer[22 + i * 20] = ((rip->entries[i].metric >> 16) & 0x000000FF);
    buffer[23 + i * 20] = ((rip->entries[i].metric >> 24) & 0x000000FF);
  }
  return len;
}
