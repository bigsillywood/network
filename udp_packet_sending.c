#include<stdio.h>
#include<winsock2.h>
#include <windows.h>
int main(){
    SetConsoleOutputCP(CP_UTF8);
    WORD sockVersion = MAKEWORD(2, 2);
    WSADATA wsaData;
    WSAStartup(sockVersion, &wsaData);
    SOCKET udpsocket=socket(AF_INET,SOCK_DGRAM,0);
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        printf("WSAStartup 失败，错误码: %d\n", result);
        return 1;
    }
    if(udpsocket==INVALID_SOCKET){
        printf("创建套接字失败,错误码:%d\n",WSAGetLastError());
        return 1;
    }
    struct sockaddr_in addr;
    addr.sin_family=AF_INET;
    addr.sin_port=htons(9999);
    addr.sin_addr.S_un.S_addr=inet_addr("127.0.0.1");
    char *data="hello,myself";

    
    
    int ret=sendto(udpsocket,data,strlen(data),0,(struct sockaddr *)&addr,sizeof(addr));
    if(ret==SOCKET_ERROR){
        printf("发送数据失败\n");
        return 1;
    }else{
        printf("发送数据成功\n");
    }
    closesocket(udpsocket);
    WSACleanup();
    return 0;
}