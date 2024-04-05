#include<errno.h>
#include"packet_constructor.h"
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
    tcp->th_sum=0x0000;
    tcp->th_sum=calculate_checksum((uint8_t*)pseudogram,psize);
    free(pseudogram);
}
//构造原始数据包，传入参数分别为构造缓冲区，缓冲区长度（一般来说调用之前会计算好，但是还是需要检查一下），包类型,网络层，网络层选项，网络层选项长度，应用层，应用层选项，应用层选项长度，数据，数据长度
int raw_packet_constructor(u_int type,u_char *buffer,u_int buffer_size,u_char *i_head,u_char *i_opt,u_int i_opt_len,u_char *a_head,u_char *a_opt,u_int a_opt_len,u_char *data,u_int data_len){
    switch (type)
    {
    case IPV4_TCP:{
        int flag=buffer_size-20-i_opt_len-20-a_opt_len-data_len;
        if(flag<0){
            printf("buffer does't have sufficient space");
            return 0;
        }else{
            u_char *buffer_index=buffer;
            struct ipheader *ip=(struct ipheader*)i_head;
            htonipheader(ip);
            memcpy(buffer_index,ip,20);
            buffer_index+=20;
            memcpy(buffer_index,i_opt,i_opt_len);
            buffer_index+=i_opt_len;
            struct tcpheader *tcp=(struct tcpheader*)a_head;
            htontcpheader(tcp);
            calculate_tcp_cheksum(ip,tcp,a_opt,a_opt_len,data,data_len);
            memcpy(buffer_index,tcp,20);
            buffer_index+=20;
            memcpy(buffer_index,a_opt,a_opt_len);
            buffer_index+=a_opt_len;
            memcpy(buffer_index,data,data_len);
            buffer_index+=data_len;
        }
        
    

        break;
    }
        
    default:{
        break;
    }
    }



    return 1;
}
void send_raw_packet(u_char *buffer_packet,u_int length,struct ipheader *ip){
    printf("准备发送数据包\n");
    struct sockaddr_in dest_info;
    int enable=1;
    //创建一个原始套接字,设置为原始数据包，IPPROTO_RAW
    SOCKET sock=socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
    
    if(sock==INVALID_SOCKET){
        printf("创建套接字失败,错误码:%s\n",strerror(errno));
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
    close(sock);
}