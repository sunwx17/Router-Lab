#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
  // TODO:
  //return true;

  uint8_t ihl = packet[0] & 0x0F;
  uint16_t checksum_given = (packet[10] << 8) + (packet[11]);
  int32_t sum = 0;
  for (uint8_t i = 0; i < (ihl << 2); i += 2) {
    if (i != 10){
      sum += (packet[i] << 8) + (packet[i + 1]);
      while((sum & 0xFFFF0000) != 0) {
        sum = ((sum >> 16) & 0x0000FFFF) + (sum & 0x0000FFFF);
      }
    }
  }
  return ((~sum) & 0x0000FFFF) == checksum_given;
}
