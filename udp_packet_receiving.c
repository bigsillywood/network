#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <string.h>

int main() {
    SetConsoleOutputCP(CP_UTF8);
    WORD sockVersion = MAKEWORD(2, 2);
    WSADATA wsaData;
    int result = WSAStartup(sockVersion, &wsaData);
    if (result != 0) {
        printf("WSAStartup 失败，错误码: %d\n", result);
        return 1;
    }

    SOCKET udpsocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpsocket == INVALID_SOCKET) {
        printf("创建套接字失败，错误码: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9999); // 绑定到端口9999
    addr.sin_addr.S_un.S_addr = htonl(INADDR_ANY); // 绑定到所有网络接口

    if (bind(udpsocket, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        printf("绑定套接字失败，错误码: %d\n", WSAGetLastError());
        closesocket(udpsocket);
        WSACleanup();
        return 1;
    }

    char data_buffer[100];
    struct sockaddr_in addr2;
    int addr_len = sizeof(addr2);

    while (1) {
        memset(data_buffer, 0, sizeof(data_buffer));
        int ret = recvfrom(udpsocket, data_buffer, sizeof(data_buffer) - 1, 0, (struct sockaddr *)&addr2, &addr_len);
        if (ret == SOCKET_ERROR) {
            printf("接收数据失败，错误码: %d\n", WSAGetLastError());
        } else {
            printf("接收数据成功\n");
            printf("接收到的数据: %s\n", data_buffer);
            // 可以使用 addr2 获取发送方的地址信息，例如 addr2.sin_addr.S_un.S_addr 获取发送方的 IP 地址
        }
    }

    closesocket(udpsocket);
    WSACleanup();
    return 0;
}
