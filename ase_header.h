#ifndef ASE_HEADER_H
#define ASE_HEADER_H

#include <netinet/in.h>

#define ERRBUF_SIZ 1024
#define SNAPLEN 65536
#define BUF_SIZ 1024

#pragma pack(push, 2)
struct mine
{
    uint8_t des_mac[6]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    uint8_t src_mac[6];
    uint16_t eth_type=0x0608;

    uint16_t hrd_type=0x0100;//2
    uint16_t proto_type=0x0008;//4
    uint8_t hrd_len=0x06;//5
    uint8_t proto_len=0x04;//6
    uint16_t oper=0x0200;//8
    uint8_t s_mac[6]; //14
    struct in_addr s_ip; // 18
    uint8_t t_mac[6]={0x00,0x00,0x00,0x00,0x00,0x00}; //24
    struct in_addr t_ip; // 28
};
#pragma pack(pop)

struct eth_header
{
    uint8_t des_mac[6];
    uint8_t src_mac[6];
    uint16_t eth_type;
    //14bytes
};

#pragma pack(push, 2)
struct arp_header
{
    uint16_t hrd_type;//2
    uint16_t proto_type;//4
    uint8_t hrd_len;//5
    uint8_t proto_len;//6
    uint16_t oper;//8
    uint8_t s_mac[6]; //14
    struct in_addr s_ip; // 18
    uint8_t t_mac[6]; //24
    struct in_addr t_ip; // 28
};
#pragma pack(pop)

struct ip_header
{
    uint8_t ip_version : 4;
    uint8_t ip_header_length : 4;
    uint8_t ip_TOS;
    uint16_t ip_total_length;
    uint16_t ip_iden;
    uint8_t flag_x : 1;
    uint8_t flag_D : 1;
    uint8_t flag_M : 1;
    uint8_t offset_part_1 : 5;
    uint8_t offset_part_2;
    uint8_t TTL;
    uint8_t ip_protocol;
    uint16_t chk_sum;
    struct in_addr ip_src_add;
    struct in_addr ip_des_add;
    //20bytes
};

struct tcp_header
{
    uint16_t src_port;
    uint16_t des_port;
    uint32_t sqn_num;
    uint32_t ack_num;
    uint8_t offset : 4;
    uint8_t ns : 1;
    uint8_t reserve : 3;
    uint8_t flag_cwr : 1;
    uint8_t flag_ece : 1;
    uint8_t flag_urgent : 1;
    uint8_t flag_ack : 1;
    uint8_t flag_push : 1;
    uint8_t flag_reset : 1;
    uint8_t flag_syn : 1;
    uint8_t flag_fin : 1;
    uint16_t window;
    uint16_t chk_sum;
    uint16_t urgent_point;
    //20bytes
};
#endif
