#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len) {
  // TODO:  
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
  if (((~sum) & 0x0000FFFF) != checksum_given) {
    return false;
  }
  uint16_t ttl_protocol_old = (packet[8] << 8) + (packet[9]);
  packet[8] = packet[8] - 1;
  uint16_t ttl_protocol_new = (packet[8] << 8) + (packet[9]);
  uint32_t checksum_new = (~checksum_given & 0x0000FFFF) + (~ttl_protocol_old & 0x0000FFFF) + ttl_protocol_new;
  //if (checksum_new < 0) checksum_new--;//why???
  while((checksum_new & 0xFFFF0000) != 0) {
    checksum_new = ((checksum_new >> 16) & 0x0000FFFF) + (checksum_new & 0x0000FFFF);
  }
  checksum_new = ~checksum_new;
  packet[10] = (checksum_new >> 8) & 0x00FF;
  packet[11] = checksum_new & 0x00FF;  
  return true;
}
