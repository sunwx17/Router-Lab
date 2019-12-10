#ifndef ROUTER_H
#define ROUTER_H

#include <stdint.h>
#include <stdio.h>
#include <string>

extern std::string ip_string(uint32_t addr);

// 路由表的一项
typedef struct {
    uint32_t addr; // 地址
    uint32_t len; // 前缀长度
    uint32_t if_index; // 出端口编号
    uint32_t nexthop; // 下一条的地址，0 表示直连
    // 为了实现 RIP 协议，需要在这里添加额外的字段
    uint32_t metric;
    void print() {
        printf("Routing Table Entry:\n\taddr: %08x(%s)\n\tlen: %d\n\tif_index: %d\n\tnexthop: %08x(%s)\n\tmetric: %d\n", addr, ip_string(addr).c_str(), len, if_index, nexthop, ip_string(nexthop).c_str(), metric);
    }
} RoutingTableEntry;

#endif