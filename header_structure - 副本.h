#include<pcap.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>

// 以太网头部
// 目标主机地址6字节
// 源主机地址6字节
// 协议类型2字节
enum packet_type{
    IPV4_TCP=1,
    IPV4_UDP=2,
    IPV4_ICMP=3,

    IPV6_TCP=4,
    IPV6_UDP=5,
    IPV6_ICMP=6,

    IPV4_TCP_VLAN=7,
    IPV4_UDP_VLAN=8,
    IPV4_ICMP_VLAN=9,

    IPV6_TCP_VLAN=10,
    IPV6_UDP_VLAN=11,
    IPV6_ICMP_VLAN=12,
    RAW=13,
    ARP=14,
    ARP_VLAN=15
};


struct ethheader {
    u_char ether_dhost[6]; // 目标主机的地址
    u_char ether_shost[6]; // 源主机的地址
    u_short ether_type; // 协议类型
};
struct ethheader_vlan {
    u_char ether_dhost[6]; // 目标主机的地址
    u_char ether_shost[6]; // 源主机的地址
    u_char vlan[4]; // vlan标签
    u_short ether_type; // 协议类型
};

struct arpheader {
    u_short ar_hrd; // 硬件类型
    u_short ar_pro; // 协议类型
    u_char ar_hln; // 硬件地址长度
    u_char ar_pln; // 协议地址长度
    u_short ar_op; // 操作类型
    u_char ar_sha[6]; // 发送方硬件地址
    u_char ar_sip[4]; // 发送方协议地址
    u_char ar_tha[6]; // 目标硬件地址
    u_char ar_tip[4]; // 目标协议地址
};


struct ipheader {
  unsigned char      iph_ihl:4,iph_ver:4; // IP头长度和版本，前4位是版本号，后4位是头部长度
  unsigned char      iph_tos;              // 服务类型，8位，1字节
  unsigned short int iph_len;              // 总长度16位，两个字节
  unsigned short int iph_ident;            // 唯一标识符16位，两个字节
  unsigned short int iph_offset:13,
                     iph_flag:3;         // 标志位3位，片偏移13位
  unsigned char      iph_ttl;              // 生存时间8位，1字节
  unsigned char      iph_protocol;         // 协议类型8位，1字节
  unsigned short int iph_chksum;           // 头部校验和16位，两个字节
  struct in_addr     iph_sourceip;         // 源IP地址32位，四个字节
  struct in_addr     iph_destip;           // 目的IP地址32位，四个字节
};
struct pseudo_header {
    struct in_addr source_address;
    struct in_addr dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short int tcp_length;
};
struct ipv6header {
    unsigned int iph_ver:4, iph_priority:8, iph_flow:20; // 版本，优先级，流标签
    unsigned short int iph_len; //有效载荷长度
    unsigned char iph_nexthdr; // 下一个头部
    unsigned char iph_hoplimit; // 跳数限制
    struct in6_addr iph_sourceip; // 源IP地址
    struct in6_addr iph_destip; // 目的IP地址
};

struct udpheader {
    u_short uh_sport; // 源端口16位，两个字节
    u_short uh_dport; // 目的端口16位，两个字节
    u_short uh_ulen; // UDP数据包长度16位，两个字节
    u_short uh_sum; // 校验和16位，两个字节
};
struct tcpheader {
    unsigned short th_sport; // 源端口16位，两个字节
    unsigned short th_dport; // 目的端口16位，两个字节
    unsigned int th_seq; // 序列号32位，四个字节
    unsigned int th_ack; // 确认号32位，四个字节
    unsigned short  control_flags:6,
                    reserved:6,
                    Data_Offset:4; // 数据偏移，4位，保留，4位
    unsigned short th_win; // 窗口大小16位，两个字节
    unsigned short th_sum; // 校验和16位，两个字节
    unsigned short th_urp; // 紧急指针16位，两个字节
};

struct icmpheader {
    u_char icmp_type; // 类型
    u_char icmp_code; // 代码
    u_short icmp_chksum; // 校验和
};

typedef struct tcp_packet{
    u_char *raw_data;
    unsigned int raw_length;
    struct ethheader *eth;
    struct ipheader *ip;
    u_char *ip_option;
    struct tcpheader *tcp;
    u_char *tcp_option;
    u_char *data;
    
}tcp_packet;

typedef struct tcp_packet_vlan{
    u_char *raw_data;
    unsigned int raw_length;
    struct ethheader_vlan *eth;
    struct ipheader *ip;
    u_char *ip_option;
    struct tcpheader *tcp;
    u_char *tcp_option;
    u_char *data;
    
}tcp_packet_vlan;

typedef struct udp_packet{
    u_char *raw_data;
    unsigned int raw_length;
    struct ethheader *eth;
    struct ipheader *ip;
    u_char *ip_option;
    struct udpheader *udp;
    u_char *data;
    
}udp_packet;

typedef struct udp_packet_vlan{
    u_char *raw_data;
    unsigned int raw_length;
    struct ethheader_vlan *eth;
    struct ipheader *ip;
    u_char *ip_option;
    struct udpheader *udp;
    u_char *data;
    
}udp_packet_vlan;


typedef struct icmp_packet{
    u_char *raw_data;
    unsigned int raw_length;
    struct ethheader *eth;
    struct ipheader *ip;
    u_char *ip_option;
    struct icmpheader *icmp;
    u_char *data;
    
}icmp_packet;

typedef struct icmp_packet_vlan{
    u_char *raw_data;
    unsigned int raw_length;
    struct ethheader_vlan *eth;
    struct ipheader *ip;
    u_char *ip_option;
    struct icmpheader *icmp;
    u_char *data;
    
}icmp_packet_vlan;





typedef struct tcp_ipv6_packet{
    u_char *raw_data;
    unsigned int raw_length;
    struct ethheader *eth;
    struct ipv6header *ip;
    struct tcpheader *tcp;
    u_char *tcp_option;
    u_char *data;
    
}tcp_ipv6_packet;

typedef struct udp_ipv6_packet{
    u_char *raw_data;
    unsigned int raw_length;
    struct ethheader *eth;
    struct ipv6header *ip;
    struct udpheader *udp;
    u_char *data;
    
}udp_ipv6_packet;

typedef struct icmp_ipv6_packet{
    u_char *raw_data;
    unsigned int raw_length;
    struct ethheader *eth;
    struct ipv6header *ip;
    struct icmpheader *icmp;
    u_char *data;
    
}icmp_ipv6_packet;



typedef struct tcp_ipv6_packet_vlan{
    u_char *raw_data;
    unsigned int raw_length;
    struct ethheader_vlan *eth;
    struct ipv6header *ip;
    struct tcpheader *tcp;
    u_char *ip_option;
    u_char *data;
    
}tcp_ipv6_packet_vlan;

typedef struct udp_ipv6_packet_vlan{
    u_char *raw_data;
    unsigned int raw_length;
    struct ethheader_vlan *eth;
    struct ipv6header *ip;
    struct udpheader *udp;
    u_char *data;
    
}udp_ipv6_packet_vlan;

typedef struct icmp_ipv6_packet_vlan{
    u_char *raw_data;
    unsigned int raw_length;
    struct ethheader_vlan *eth;
    struct ipv6header *ip;
    struct icmpheader *icmp;
    u_char *data;
    
}icmp_ipv6_packet_vlan;

typedef struct arp_packet{
    u_char *raw_data;
    unsigned int raw_length;
    struct ethheader *eth;
    struct arpheader *arp; 
}arp_packet;

typedef struct arp_packet_vlan{
    u_char *raw_data;
    unsigned int raw_length;
    struct ethheader_vlan *eth;
    struct arpheader *arp;
}arp_packet_vlan;

typedef struct raw_packet{
    u_char *data;
    unsigned int length;
    
}raw_packet;


typedef struct packet_args{
    u_char *packet_buffer;
    u_int packet_type;
    //写这个是为了获取数据长度，用来做减法的
    u_int packet_length;
}packet_args;
