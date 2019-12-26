#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "rip.h"


/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/

struct RoutingList {
  RoutingTableEntry entry;
  RoutingList * next = NULL;
  RoutingList() {
  }
  RoutingList(RoutingTableEntry e) {
    entry = e;
  }
} first;

int entry_num = 0;

/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 * 
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len 匹配。
 */
void update(bool insert, RoutingTableEntry entry) {
  // TODO:
  
  #ifdef DEBUG_OUTPUT
  printf("update\n");
  entry.print();
  #endif
  RoutingList * before;
  RoutingList * now = &first;
  RoutingList * next = first.next;
  while (next != NULL) {
    before = now;
    now = next;
    next = now->next;
    if (now->entry.addr == entry.addr && now->entry.len == entry.len){
      if (insert) {
        now->entry.if_index = entry.if_index;
        now->entry.nexthop = entry.nexthop;
        entry_num += 1;
      }
      else {
        before->next = next;
        delete now;
        entry_num -= 1;
      }
      return;
    }
  }
  if (insert) {
    RoutingList * newRouting = new RoutingList(entry);
    now->next = newRouting;
    entry_num += 1;
  }
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index, uint32_t *metric) {
  // TODO:
  
  bool res = false;
  RoutingList * now = &first;
  RoutingList * next = first.next;
  uint32_t max_len = 0;
  while (next != NULL) {
    now = next;
    next = now->next;
    if (now->entry.len > max_len) {
      uint32_t mask = (uint32_t)(((uint64_t)(0x0000000000000001) << now->entry.len) - 1);
      if ((addr & mask) == (now->entry.addr & mask)) {
        *nexthop = now->entry.nexthop;
        *if_index = now->entry.if_index;
        *metric = now->entry.metric;
        max_len = now->entry.len;
        res = true;
      }
    }
  }
  return res;
}

void get_packet(vector<RipPacket> * res, uint32_t if_index) {
  
  RoutingList * now = &first;
  RoutingList * next = first.next;
  uint32_t l = 0;
  RipPacket temp_p;
  while (next != NULL) {
    now = next;
    next = now->next;
    if (now->entry.if_index == if_index){
      continue;
    }
    temp_p.command = 2;
    temp_p.entries[l].addr = now->entry.addr;
    temp_p.entries[l].mask = (((uint64_t)1 << now->entry.len) - 1);
    temp_p.entries[l].nexthop = now->entry.nexthop;
    temp_p.entries[l].metric = now->entry.metric;
    l++;
    if (l >= 24) {
      temp_p.numEntries = l;
      res->push_back(temp_p);
      l = 0;
    }
  }
  if (l < 24) {
    temp_p.numEntries = l;
    res->push_back(temp_p);
  }
}


void print_all_entry(){
  if (entry_num > 25) {
    RoutingList * now = &first;
    RoutingList * next = first.next;
    uint32_t l = 0;
    while (next != NULL) {
      now = next;
      next = now->next;
      printf("the %d entry:\n", l);
      now->entry.print();
      l++;
    }
  }
  else {
    printf("total %d entries\n", entry_num);
  }
}