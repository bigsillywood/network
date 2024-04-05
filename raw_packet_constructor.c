#include<stdio.h>
#include<winsock2.h>
#include <windows.h>
#include <pcap.h>

#include "header_structure.h"
#include "sniff.h"


#define buffer_size 3096
//构造一个UDP数据包,buffer_packet将会作为数据包的缓冲区并且返回
void construct_raw_udp_packet(struct ipheader *ip_1,u_char *ip_opt,u_int ip_opt_len,struct udpheader *udp1,u_char *buffer_packet,u_int BUFFER_SIZE,u_char *data2){
    //也许可能要用以太网头部如果需要+sizeof(struct ethheader)
    //填充IP头部
    
    struct ipheader *ip=(struct ipheader *)(buffer_packet);
    ip->iph_ihl=ip_1->iph_ihl;
    ip->iph_ver=ip_1->iph_ver;
    ip->iph_tos=ip_1->iph_tos;
    ip->iph_len=ip_1->iph_len;
    ip->iph_ident=ip_1->iph_ident;
    ip->iph_flag=ip_1->iph_flag;
    ip->iph_offset=ip_1->iph_offset;
    ip->iph_ttl=ip_1->iph_ttl;
    ip->iph_protocol=ip_1->iph_protocol;
    ip->iph_chksum=ip_1->iph_chksum;
    ip->iph_sourceip=ip_1->iph_sourceip;
    ip->iph_destip=ip_1->iph_destip;
    u_char *ip_opt1=(u_char*)(buffer_packet+sizeof(struct ipheader));
    memcpy(ip_opt1,ip_opt,ip_opt_len);
    //填充udp头部
    struct udpheader *udp=(struct udpheader *)(buffer_packet+sizeof(struct ipheader)+ip_opt_len);
    udp->uh_sport=udp1->uh_sport;
    udp->uh_dport=udp1->uh_dport;
    udp->uh_ulen=udp1->uh_ulen;
    udp->uh_sum=udp1->uh_sum;
    //填充数据
    u_char *data=buffer_packet+sizeof(struct ipheader)+ip_opt_len+sizeof(struct udpheader);
    int data_len=strlen(data2);
    if (sizeof(struct ipheader)+ip_opt_len+ sizeof(struct udpheader) + data_len<= BUFFER_SIZE) {
        memcpy(data, data2, data_len);
        printf("UDP数据包构造成功\n");
    } else {
    // 处理错误情况：缓冲区太小
        printf("UDP数据包构造失败,缓冲区太小\n");
    }
}
//构造一个TCP数据包
void construct_raw_tcp_packet(struct ipheader *ip_1,u_char *ip_opt,u_int ip_opt_len, struct tcpheader *tcp1,u_char *tcp_opt,u_int tcp_opt_len,u_char *buffer_packet,u_int BUFFER_SIZE,u_char *data2){
    //也许可能要用以太网头部如果需要+sizeof(struct ethheader)
    //填充IP头部
    struct ipheader *ip=(struct ipheader *)(buffer_packet);
    ip->iph_ihl=ip_1->iph_ihl;
    ip->iph_ver=ip_1->iph_ver;
    ip->iph_tos=ip_1->iph_tos;
    ip->iph_len=ip_1->iph_len;
    ip->iph_ident=ip_1->iph_ident;
    ip->iph_flag=ip_1->iph_flag;
    ip->iph_offset=ip_1->iph_offset;
    ip->iph_ttl=ip_1->iph_ttl;
    ip->iph_protocol=ip_1->iph_protocol;
    ip->iph_chksum=ip_1->iph_chksum;
    ip->iph_sourceip=ip_1->iph_sourceip;
    ip->iph_destip=ip_1->iph_destip;
    u_char *ip_opt1=(u_char*)(buffer_packet+sizeof(struct ipheader));
    memcpy(ip_opt1,ip_opt,ip_opt_len);
    //填充tcp头部
    struct tcpheader *tcp=(struct tcpheader *)(buffer_packet+sizeof(struct ipheader)+ip_opt_len);
    tcp->th_sport=tcp1->th_sport;
    tcp->th_dport=tcp1->th_dport;
    tcp->th_seq=tcp1->th_seq;
    tcp->th_ack=tcp1->th_ack;
    tcp->control_flags=tcp1->control_flags;
    tcp->reserved=tcp1->reserved;
    tcp->Data_Offset=tcp1->Data_Offset;
    tcp->th_win=tcp1->th_win;
    tcp->th_sum=tcp1->th_sum;
    tcp->th_urp=tcp1->th_urp;
    u_char *tcp_opt1=(u_char*)(buffer_packet+sizeof(struct ipheader)+ip_opt_len+sizeof(struct tcpheader));
    memcpy(tcp_opt1,tcp_opt,tcp_opt_len);
    //填充数据
    u_char *data=buffer_packet+sizeof(struct ipheader)+sizeof(struct tcpheader)+ip_opt_len+tcp_opt_len;
    int data_len=sizeof(data2);
    if (sizeof(struct ipheader) +ip_opt_len+sizeof(struct tcpheader)+tcp_opt_len + data_len<= BUFFER_SIZE) {
        memcpy(data, data2, data_len);
        printf("TCP数据包构造成功\n");
    } else {
    // 处理错误情况：缓冲区太小
        printf("TCP数据包构造失败,缓冲区太小\n");
    }
}
void construct_raw_icmp_packet(struct ipheader *ip_1,u_char *ip_opt,u_int ip_opt_len,struct icmpheader *icmp1,u_char *buffer_packet,u_int BUFFER_SIZE,u_char *data2){
    //也许可能要用以太网头部如果需要+sizeof(struct ethheader)
    //填充IP头部
    struct ipheader *ip=(struct ipheader *)(buffer_packet);
    ip->iph_ihl=ip_1->iph_ihl;
    ip->iph_ver=ip_1->iph_ver;
    ip->iph_tos=ip_1->iph_tos;
    ip->iph_len=ip_1->iph_len;
    ip->iph_ident=ip_1->iph_ident;
    ip->iph_flag=ip_1->iph_flag;
    ip->iph_offset=ip_1->iph_offset;
    ip->iph_ttl=ip_1->iph_ttl;
    ip->iph_protocol=ip_1->iph_protocol;
    ip->iph_chksum=ip_1->iph_chksum;
    ip->iph_sourceip=ip_1->iph_sourceip;
    ip->iph_destip=ip_1->iph_destip;
    u_char *ip_opt1=(u_char*)(buffer_packet+sizeof(struct ipheader));
    memcpy(ip_opt1,ip_opt,ip_opt_len);
    //填充icmp头部
    struct icmpheader *icmp=(struct icmpheader *)(buffer_packet+sizeof(struct ipheader)+ip_opt_len);
    icmp->icmp_type=icmp1->icmp_type;
    icmp->icmp_code=icmp1->icmp_code;
    icmp->icmp_chksum=icmp1->icmp_chksum;
    //填充数据
    u_char *data=buffer_packet+sizeof(struct ipheader)+ip_opt_len+sizeof(struct icmpheader);
    int data_len=sizeof(data2);
    if (sizeof(struct ipheader) + ip_opt_len+sizeof(struct icmpheader) + data_len<= BUFFER_SIZE) {
        memcpy(data, data2, data_len);
        printf("ICMP数据包构造成功\n");
    } else {
    // 处理错误情况：缓冲区太小
        printf("ICMP数据包构造失败,缓冲区太小\n");
    }
}
//使用时，记住一定要先调用此方法，然后再调用htonipheader方法
u_int get_ip_option_length(struct ipheader *ip){
    return (ip->iph_ihl-5)*4;
}
//使用时，记住一定要先调用此方法，然后再调用htontcpheader方法
u_int get_tcp_option_length(struct tcpheader *tcp){
    return (tcp->Data_Offset-5)*4;
}
//接下来的方法用于对齐ip头部
void htonipheader(struct ipheader *ip){
    u_short temp2 = htons(ip->iph_flag << 13) | (ip->iph_offset & 0x1FFF);
    memcpy((u_char *)ip+6,&temp2,2);
}
//接下来的方法用于对齐tcp头部
void htontcpheader(struct tcpheader *tcp){
    u_short temps = htons((tcp->Data_Offset << 12) | (tcp->reserved << 9) | tcp->control_flags);
    memcpy((u_char *)tcp+12,&temps,2);
}
//这个只能发送icmp数据包，其他的数据包请使用pcap库，因为windows下的原始套接字不支持发送tcp和udp数据包
void send_raw_packet(u_char *buffer_packet,u_int length,struct ipheader *ip){
    printf("准备发送数据包\n");
    struct sockaddr_in dest_info;
    int enable=1;
    //创建一个原始套接字,设置为原始数据包，IPPROTO_RAW
    SOCKET sock=socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
    
    if(sock==INVALID_SOCKET){
        printf("创建套接字失败,错误码:%d\n",WSAGetLastError());
        return;
    }
    printf("套接字创建成功\n");
    setsockopt(sock,IPPROTO_IP,IP_HDRINCL,(const char*)&enable,sizeof(enable));
    
    //设置IPV4地址族
    dest_info.sin_family=AF_INET;
    //设置目的地址为ip头部中的目的地址，端口在应用层协议中设置
    dest_info.sin_addr=ip->iph_destip;
    //sendto函数发送数据包,参数分别是套接字，数据包缓冲区，数据包长度，标志位，目的地址，目的地址长度
    //返回值是发送的字节数
    if(sendto(sock,buffer_packet,length,0,(struct sockaddr *)&dest_info,sizeof(dest_info))<0){
       printf("发送失败\n");
    }else{
        printf("发送成功\n");
    }
    closesocket(sock);
}
// 计算校验和的函数，输入是一个指向大端顺序字节的指针和字节的数量
uint16_t calculate_checksum(uint8_t *buffer, size_t length) {
    uint32_t sum = 0;

    // 处理每个16位的块
    for (size_t i = 0; i < length; i += 2) {
        uint16_t word;
        if (i + 1 < length) {
            // 从大端转换为主机字节序以进行计算
            word = ntohs(*(uint16_t *)(buffer + i));
        } else {
            // 处理奇数长度的情况，最后一个字节后面添加0
            word = buffer[i] << 8;
        }
        sum += word;

        // 处理溢出
        if (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + 1;
        }
    }

    // 取反获取校验和，并转换为大端字节序以便发包
    return htons(~(uint16_t)sum);
}
//注意这里的都是大端顺序，请一定在调用这个方法之前调用htonipheader方法和htontcpheader方法
u_short checksum1(u_short *buffer, int size);
void calculate_tcp_cheksum(struct ipheader *ip,struct tcpheader *tcp,u_char *tcp_opt,u_int tcp_opt_len,u_char *data,u_int data_len){
    struct pseudo_header psh;
    psh.source_address=ip->iph_sourceip;
    psh.dest_address=ip->iph_destip;
    psh.placeholder=0;
    psh.protocol=IPPROTO_TCP;
    psh.tcp_length=htons(sizeof(struct tcpheader)+data_len);
    int psize=sizeof(struct pseudo_header)+sizeof(struct tcpheader)+tcp_opt_len+data_len;
    u_char *pseudogram=(u_char *)malloc(psize);
    memcpy(pseudogram,(char *)&psh,sizeof(struct pseudo_header));
    memcpy(pseudogram+sizeof(struct pseudo_header),tcp,sizeof(struct tcpheader));
    memcpy(pseudogram+sizeof(struct pseudo_header)+sizeof(struct tcpheader),tcp_opt,tcp_opt_len);
    memcpy(pseudogram+sizeof(struct pseudo_header)+sizeof(struct tcpheader)+tcp_opt_len,data,data_len);
    tcp->th_sum=calculate_checksum((uint8_t*)pseudogram,psize);
    free(pseudogram);
}

u_short checksum1(u_short *buffer, int size) {
    u_long cksum = 0;
    while (size > 1) {
        cksum += ntohs(*buffer++);  // 转换为主机字节序并累加
        size -= sizeof(u_short);
    }
    if (size) {
        cksum += (*(u_char *)buffer) << 8;  // 处理剩余的单个字节
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    cksum +=(cksum>>16);
    printf("校验和为:%X\n",((u_short)(~cksum)));
    return htons((u_short)(~cksum));  // 转换为网络字节序并取反
}




/*int main(){
    SetConsoleOutputCP(CP_UTF8);
    WORD sockVersion = MAKEWORD(2, 2);
    WSADATA wsaData;
    WSAStartup(sockVersion, &wsaData);
    struct ipheader ip;
    struct udpheader udp;

    char *data="hello,myself";
    int length=strlen(data);
    char *buffer_packet=(char *)malloc(sizeof(struct ipheader)+sizeof(struct udpheader)+length);
    memset(buffer_packet,0,sizeof(struct ipheader)+sizeof(struct udpheader)+length);
    //udp头部，源端口，目的端口，数据包长度，校验和
    udp.uh_sport=htons(12345);
    udp.uh_dport=htons(9999);
    udp.uh_ulen=htons(sizeof(struct udpheader)+length);
    udp.uh_sum=0;

    // ip头部，ip设置ipv4
    ip.iph_ver=4;
    //ip头部长度,5位代表ip头部长度为20字节，如果有选项字段则会增加，最高为60字节，及15*4
    ip.iph_ihl=5;
    ip.iph_len=sizeof(struct ipheader)+sizeof(struct udpheader)+length;
    //响应时间
    ip.iph_ttl=255;
    //协议类型
    ip.iph_protocol=IPPROTO_UDP;

    ip.iph_chksum=0;
    ip.iph_sourceip.s_addr=inet_addr("127.0.0.1");//源地址
    ip.iph_destip.s_addr=inet_addr("127.0.0.1");//目的地址

    u_char *ip_opt=(u_char *)malloc(0);
    int ip_opt_len=get_ip_option_length(&ip);
    construct_raw_udp_packet(&ip,ip_opt,ip_opt_len,&udp,buffer_packet,ip.iph_len,data);
    send_raw_packet(buffer_packet,ip.iph_len,&ip);
    free(buffer_packet);
}*/