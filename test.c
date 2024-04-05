#include<stdio.h>
#include<pcap.h>
#include<stdlib.h>
#include<string.h>
#include"sniff.h"
int main(){
    pcap_if_t *alldev;
    pcap_if_t *dev;
    pcap_if_t *allowdev;
    char err[PCAP_ERRBUF_SIZE];
    if(pcap_findalldevs(&alldev,err)==-1){
        printf("网卡获取失败");
    }
    dev=alldev;
    /*这段代码是windows的，放在linux不行，linux代码如下
    while(dev!=NULL){
        if(dev->addresses!=NULL && dev->addresses->addr!= NULL){
            printf("网卡名:%s\n",dev->name);
            if(dev->addresses->addr->sa_family==AF_INET){
                struct sockaddr_in *sin = (struct sockaddr_in *)dev->addresses->addr;
                char *ip = inet_ntoa(sin->sin_addr);
                printf("网卡地址: %s\n", ip);
                if(strcmp(ip,"192.168.1.119")==0){
                    allowdev=dev;
                }
            }
        }
        dev=dev->next;
    }*/
    struct pcap_addr *addr;
    while(dev!=NULL){
        printf("网卡名:%s--",dev->name);
        for(addr = dev->addresses; addr != NULL; addr = addr->next) {
            if(addr->addr != NULL && addr->addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)addr->addr;
                char *ip = inet_ntoa(sin->sin_addr);
                printf("网卡地址: %s\n", ip);
                if(strcmp(ip, "192.168.1.119") == 0) {
                    allowdev = dev;
                }
            }
        }
        printf("\n");
        dev=dev->next;
    }
    
    if (allowdev == NULL || allowdev->name == NULL) {
        fprintf(stderr, "Device or device name is NULL.\n");
        return 0;
    // 适当的错误处理
    }
    pcap_t *pt =pcap_open_live(allowdev->name,65535,1,1000,err);
    if(pt==NULL){
        printf("打开网卡失败，错误信息 %s\n", err);
    }
    char *filter_string="";
    struct bpf_program filter;
    bpf_u_int32 netmask;
    if(pcap_compile(pt,&filter,filter_string,0,PCAP_NETMASK_UNKNOWN)==-1){
        printf("编译过滤器失败\n");
        pcap_close(pt);
    }
    if(pcap_setfilter(pt,&filter)==-1){
        printf("设置过滤器失败\n");
        pcap_close(pt);
    }
    u_char *pbuffer=malloc(1024);
    pcap_loop(pt,1,packet_analyze,(u_char *)pbuffer);
    packet_args *pa=(packet_args*)pbuffer;
    for(int i=0;i<pa->packet_length;i++){
        printf("%02x ",pa->packet_buffer[i]);
    }
    return 0;
}