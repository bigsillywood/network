#include<stdio.h>
#include <pcap/pcap.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "header_structure.h"
#include "sniff.h"

#define buffer_size 3096


int main(){
    SetConsoleOutputCP(CP_UTF8);
    pcap_if_t *alldev;
    pcap_if_t *dev;
    pcap_if_t *allowdev;
    char err[PCAP_ERRBUF_SIZE];
    if(pcap_findalldevs(&alldev,err)==-1){

        printf("未获取网卡，错误信息 %s\n", err);

    }
    dev=alldev;
    while(dev!=NULL){
        //printf("\n");
        //printf("网卡名字:%s\n",dev->name);
        //printf("网卡描述:%s\n",dev->description);
        if (dev->addresses != NULL && dev->addresses->addr != NULL) {
            // 只处理 IPv4 地址
            if (dev->addresses->addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)dev->addresses->addr;
                char *ip = inet_ntoa(sin->sin_addr);
                //printf("网卡地址: %s\n", ip);
                if(strcmp(ip,"192.168.1.118")==0){
                    allowdev=dev;
                }
            }
        } else {
           //printf("网卡地址: (无地址)\n");
        }
        
        dev=dev->next;
    }
    printf("选择的网卡名字:%s\n",allowdev->name);
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

    /*packet *data=(packet *)malloc(sizeof(packet));*/
    /*data->raw_data=(char *)malloc(buffer_size);*/
    //pcap_loop(pt,1,packet_handler,(u_char *)data);

    char *buffer2=malloc(sizeof(buffer_size));
    u_char *p_arg=(u_char*)malloc(buffer_size+4);
    pcap_loop(pt,1,got_pack,(u_char *)p_arg);
    printf("数据包类型:%d\n",((packet_args *)p_arg)->packet_type);
    /*for(i=0;i<data->length;i++){
        printf("%02x ",data->data[i]);
        if((i+1)%16==0){
            printf("\n");
        }
    }*/
    /*free(data);*/
    //free(data->raw_data);
    pcap_close(pt);
    pcap_freealldevs(alldev);
    return 0;
}