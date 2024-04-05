#include<stdio.h>
#include<winsock2.h>
#include <windows.h>
#include <pcap.h>


#include "header_structure.h"
#include "sniff.h"
#include "raw_packet_constructor.h"



//假设这是一个icmp的包
void packet_handle(u_char *param1, const struct pcap_pkthdr *header, const u_char *pkt_data){
    //这里是处理包的地方
    //param1将会返回一个完整的数据包结构体，里面包含我自定义的mac头部，ip头部，icmp头部，数据,以及raw数据还有len
    printf("捕获到一个icmp包\n");
    got_pack(param1,header,pkt_data);
    packet_args *param=(packet_args *)param1;
    //刚翻看之前写的代码，param1是一个带有icmp包和type的结构，需要提取出icmp包
    icmp_packet *icmp_packet1=(icmp_packet *)(param->packet_buffer);
    struct ipheader *ip=icmp_packet1->ip;
    //ip调换+
    struct in_addr temp_addr;
    memcpy(&temp_addr,&(ip->iph_sourceip),sizeof(struct in_addr));
    ip->iph_sourceip=ip->iph_destip;
    ip->iph_destip=temp_addr;

    //icmp调换
    struct icmpheader *icmp=icmp_packet1->icmp;
    icmp->icmp_type=0;
    u_char *ip_options=icmp_packet1->ip_option;
    u_char *data=icmp_packet1->data;
    u_int data_len=(param->packet_length)-sizeof(struct ipheader)-ip->iph_ihl-sizeof(struct icmpheader);
    u_int ip_option_len=get_ip_option_length(ip);
    htonipheader(ip);
    u_char *buffer_packet=malloc(sizeof(struct ipheader)+ip_option_len+sizeof(struct icmpheader)+data_len);
    construct_raw_icmp_packet(ip,ip_options,ip_option_len,icmp,buffer_packet,buffer_size,data);
    send_raw_packet(buffer_packet,ip->iph_len,ip);
    free_packet((u_char*)param);
    memset(buffer_packet,0,sizeof(struct ipheader)+ip_option_len+sizeof(struct icmpheader)+data_len);
}



int main(){
    SetConsoleOutputCP(CP_UTF8);
    pcap_if_t *alldev;
    pcap_if_t *dev;
    pcap_if_t *allowdev;
    char err[PCAP_ERRBUF_SIZE];
    if(pcap_findalldevs(&alldev,err)==-1){
        printf("未获取网卡，错误信息 %s\n", err);
    }
    for(dev=alldev;dev!=NULL;dev=dev->next){
        printf("\n");
        printf("网卡名字:%s\n",dev->name);
        printf("网卡描述:%s\n",dev->description);
        if (dev->addresses != NULL && dev->addresses->addr != NULL) {
            // 只处理 IPv4 地址
            if (dev->addresses->addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)dev->addresses->addr;
                char *ip = inet_ntoa(sin->sin_addr);
                printf("网卡地址: %s\n", ip);
                if(strcmp(ip,"192.168.1.118")==0){
                    allowdev=dev;
                }
            }
        } else {
              printf("网卡地址: (无地址)\n");
          }
    }
    pcap_t *pt =pcap_open_live(allowdev->name,65535,1,1000,err);
    if(pt==NULL){
        printf("打开网卡失败，错误信息 %s\n", err);
    }
    char *filter_string="icmp";
    struct bpf_program filter;
    bpf_u_int32 netmask;
    if(pcap_compile(pt,&filter,filter_string,0,PCAP_NETMASK_UNKNOWN)==-1){
        printf("编译过滤器失败\n");
        pcap_close(pt);
    }else{
        printf("编译过滤器成功\n");
    }
    if(pcap_setfilter(pt,&filter)==-1){
        printf("设置过滤器失败\n");
        pcap_close(pt);
    }else{
        printf("设置过滤器成功\n");
    }
    printf("开始修改icmp包并回送\n");
    u_char *packet_buffer=malloc(buffer_size);
    pcap_loop(pt,-1,packet_handle,packet_buffer);

}