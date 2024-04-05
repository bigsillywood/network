#include <winsock2.h>
#include <stdio.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib") // 链接到Winsock库

int main() {
    SetConsoleOutputCP(CP_UTF8);
    WSADATA wsaData;
    SOCKET serverSocket;
    struct sockaddr_in serverAddr;
    char* message = "Hello Server";

    // 初始化Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("Winsock initialization failed.\n");
        return 1;
    }

    // 创建套接字
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        printf("Could not create socket.\n");
        WSACleanup();
        return 1;
    }

    // 设置服务器地址结构
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1"); // 服务器IP地址，这里设置为本地回环地址
    serverAddr.sin_port = htons(5555); // 服务器端口，与服务器监听端口相同

    // 连接到服务器
    if (connect(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        printf("Connect error.\n");
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    printf("Connected to server.\n");

    // 发送消息
    if (send(serverSocket, message, strlen(message), 0) < 0) {
        printf("Send failed.\n");
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    printf("Message sent.\n");

    // 关闭套接字
    closesocket(serverSocket);
    WSACleanup(); // 清理Winsock
    return 0;
}
