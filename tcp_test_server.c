#include <winsock2.h>
#include <stdio.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib") // 链接到Winsock库

int main() {
    SetConsoleOutputCP(CP_UTF8);
    WSADATA wsaData;
    SOCKET listeningSocket;
    struct sockaddr_in serverAddr;
    struct sockaddr_in clientAddr;
    int clientAddrSize = sizeof(clientAddr);

    // 初始化Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("初始化失败\n");
        return 1;
    }

    // 创建监听套接字
    listeningSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listeningSocket == INVALID_SOCKET) {
        printf("无法创建此套接字\n");
        WSACleanup();
        return 1;
    }

    // 设置服务器地址结构
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY; // 服务器IP
    serverAddr.sin_port = htons(5555); // 服务器端口

    // 绑定套接字
    if (bind(listeningSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        printf("绑定失败\n");
        closesocket(listeningSocket);
        WSACleanup();
        return 1;
    }

    // 开始监听
    listen(listeningSocket, 5);

    printf("等待连接\n");

    // 等待连接尝试
    while (1) {
        SOCKET clientSocket = accept(listeningSocket, (struct sockaddr*)&clientAddr, &clientAddrSize);
        if (clientSocket == INVALID_SOCKET) {
            printf("接收失败\n");
            continue;
        }

        // 打印客户端IP地址
        printf("客户端ip地址为 %s\n", inet_ntoa(clientAddr.sin_addr));

        // 通常情况下，这里会进行进一步的读写操作，但我们只关心IP地址，所以直接关闭连接
        closesocket(clientSocket);
    }

    // 关闭监听套接字
    closesocket(listeningSocket);
    WSACleanup(); // 清理Winsock
    return 0;
}
