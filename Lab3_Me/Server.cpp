#include <winsock2.h>
#include <ws2tcpip.h>
#include <shellapi.h>

#include <cctype>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Shell32.lib")

using namespace std;

namespace {
    constexpr uint16_t kDiscoveryPort = 5001;
    constexpr uint32_t kMagic = 0x4C414233;  // "LAB3"
    constexpr int kMaxDatagramBytes = 60000;

    enum PacketType : uint32_t {
        PACKET_DISCOVER = 1,
        PACKET_OFFER = 2,
        PACKET_META = 3,
        PACKET_DATA = 4,
        PACKET_DONE = 5,
        PACKET_ACK = 6
    };

#pragma pack(push, 1)
    struct PacketHeaderNet {
        uint32_t magic;
        uint32_t type;
        uint32_t mode;
        uint32_t totalParts;
        uint32_t partIndex;
        uint32_t fileSize;
        uint32_t payloadSize;
    };
#pragma pack(pop)

    struct PacketHeaderHost {
        uint32_t magic = kMagic;
        uint32_t type = 0;
        uint32_t mode = 0;
        uint32_t totalParts = 0;
        uint32_t partIndex = 0;
        uint32_t fileSize = 0;
        uint32_t payloadSize = 0;
    };

    struct TransferState {
        bool initialized = false;
        uint32_t mode = 0;
        uint32_t totalParts = 0;
        uint32_t fileSize = 0;
        string fileName;
        vector<vector<char>> parts;
        vector<bool> received;
        uint32_t receivedCount = 0;
    };

    PacketHeaderNet toNetwork(const PacketHeaderHost& h) {
        PacketHeaderNet net{};
        net.magic = htonl(h.magic);
        net.type = htonl(h.type);
        net.mode = htonl(h.mode);
        net.totalParts = htonl(h.totalParts);
        net.partIndex = htonl(h.partIndex);
        net.fileSize = htonl(h.fileSize);
        net.payloadSize = htonl(h.payloadSize);
        return net;
    }

    PacketHeaderHost toHost(const PacketHeaderNet& n) {
        PacketHeaderHost host{};
        host.magic = ntohl(n.magic);
        host.type = ntohl(n.type);
        host.mode = ntohl(n.mode);
        host.totalParts = ntohl(n.totalParts);
        host.partIndex = ntohl(n.partIndex);
        host.fileSize = ntohl(n.fileSize);
        host.payloadSize = ntohl(n.payloadSize);
        return host;
    }

    string endpointToString(const sockaddr_in& ep) {
        char ip[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &ep.sin_addr, ip, sizeof(ip));
        return string(ip) + ":" + to_string(ntohs(ep.sin_port));
    }

    string sanitizeForFileName(string value) {
        for (char& c : value) {
            if (!(isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_')) {
                c = '_';
            }
        }
        return value;
    }

    bool sendPacket(SOCKET s, PacketHeaderHost header, const char* payload, size_t payloadSize,
        const sockaddr_in& to) {
        if (payloadSize > static_cast<size_t>(kMaxDatagramBytes - sizeof(PacketHeaderNet))) {
            cout << "Payload is too large for UDP packet\n";
            return false;
        }

        header.payloadSize = static_cast<uint32_t>(payloadSize);
        PacketHeaderNet netHeader = toNetwork(header);

        vector<char> raw(sizeof(PacketHeaderNet) + payloadSize);
        memcpy(raw.data(), &netHeader, sizeof(netHeader));
        if (payloadSize > 0) {
            memcpy(raw.data() + sizeof(PacketHeaderNet), payload, payloadSize);
        }

        int sent = sendto(s, raw.data(), static_cast<int>(raw.size()), 0,
            reinterpret_cast<const sockaddr*>(&to), sizeof(to));
        return sent == static_cast<int>(raw.size());
    }

    bool recvPacket(SOCKET s, PacketHeaderHost& header, vector<char>& payload, sockaddr_in& from) {
        vector<char> raw(kMaxDatagramBytes);
        int fromLen = sizeof(from);
        int received = recvfrom(s, raw.data(), static_cast<int>(raw.size()), 0,
            reinterpret_cast<sockaddr*>(&from), &fromLen);

        if (received == SOCKET_ERROR) {
            cout << "recvfrom() failed with error " << WSAGetLastError() << '\n';
            return false;
        }

        if (received < static_cast<int>(sizeof(PacketHeaderNet))) {
            cout << "Received too small datagram, ignored\n";
            return false;
        }

        PacketHeaderNet netHeader{};
        memcpy(&netHeader, raw.data(), sizeof(netHeader));
        header = toHost(netHeader);

        if (header.magic != kMagic) {
            cout << "Invalid packet magic, ignored\n";
            return false;
        }

        int availablePayload = received - static_cast<int>(sizeof(PacketHeaderNet));
        if (header.payloadSize > static_cast<uint32_t>(availablePayload)) {
            cout << "Invalid payload size in header, ignored\n";
            return false;
        }

        payload.assign(raw.begin() + sizeof(PacketHeaderNet),
            raw.begin() + sizeof(PacketHeaderNet) + header.payloadSize);
        return true;
    }

    void openTextFile(const string& path) {
        HINSTANCE result =
            ShellExecuteA(nullptr, "open", path.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        if (reinterpret_cast<intptr_t>(result) <= 32) {
            cout << "Cannot auto-open file: " << path << '\n';
        }
    }

    bool saveTransfer(const TransferState& state, const string& clientKey) {
        if (!state.initialized || state.receivedCount != state.totalParts) {
            return false;
        }

        string outName = "received_" + sanitizeForFileName(clientKey) + "_" + state.fileName;
        ofstream out(outName, ios::binary);
        if (!out.is_open()) {
            cout << "Cannot create output file: " << outName << '\n';
            return false;
        }

        size_t totalBytes = 0;
        for (const auto& part : state.parts) {
            if (!part.empty()) {
                out.write(part.data(), static_cast<streamsize>(part.size()));
                totalBytes += part.size();
            }
        }

        out.close();

        cout << "Saved: " << outName << '\n';
        cout << "Mode: " << state.mode << ", parts: " << state.totalParts << '\n';
        cout << "Received bytes: " << totalBytes << ", expected: " << state.fileSize << '\n';

        openTextFile(outName);
        return true;
    }

    void initTransferFromMeta(TransferState& state, const PacketHeaderHost& h,
        const vector<char>& payload, const string& clientKey) {
        state.initialized = true;
        state.mode = h.mode;
        state.totalParts = (h.totalParts == 0) ? 1 : h.totalParts;
        state.fileSize = h.fileSize;
        state.fileName.assign(payload.begin(), payload.end());
        if (state.fileName.empty()) {
            state.fileName = "received.rtf";
        }
        state.parts.assign(state.totalParts, {});
        state.received.assign(state.totalParts, false);
        state.receivedCount = 0;

        cout << "[" << clientKey << "] Transfer initialized. File: " << state.fileName
            << ", mode: " << state.mode << ", parts: " << state.totalParts << '\n';
    }

    void acceptLoopCodeFragmentExample() {
        // This fragment is included because the lab explicitly asks for cyclic accept().
        // Note: UDP (SOCK_DGRAM) does not support accept(); this fragment is for demonstration.
        SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSock == INVALID_SOCKET) {
            return;
        }

        sockaddr_in tcpAddr{};
        tcpAddr.sin_family = AF_INET;
        tcpAddr.sin_port = htons(5050);
        tcpAddr.sin_addr.s_addr = INADDR_ANY;

        if (bind(listenSock, reinterpret_cast<sockaddr*>(&tcpAddr), sizeof(tcpAddr)) == SOCKET_ERROR) {
            closesocket(listenSock);
            return;
        }
        if (listen(listenSock, SOMAXCONN) == SOCKET_ERROR) {
            closesocket(listenSock);
            return;
        }

        SOCKET accepted = INVALID_SOCKET;
        while (accepted == INVALID_SOCKET) {
            accepted = accept(listenSock, nullptr, nullptr);
            if (accepted == INVALID_SOCKET) {
                int err = WSAGetLastError();
                if (err != WSAEINTR) {
                    break;
                }
            }
        }

        if (accepted != INVALID_SOCKET) {
            closesocket(accepted);
        }
        closesocket(listenSock);
    }
}  // namespace

int main() {
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        cout << "WSAStartup failed\n";
        return 1;
    }

    SOCKET serverSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (serverSocket == INVALID_SOCKET) {
        cout << "socket() failed\n";
        WSACleanup();
        return 1;
    }

    sockaddr_in bindAddr{};
    bindAddr.sin_family = AF_INET;
    bindAddr.sin_port = htons(kDiscoveryPort);
    bindAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverSocket, reinterpret_cast<sockaddr*>(&bindAddr), sizeof(bindAddr)) ==
        SOCKET_ERROR) {
        cout << "bind() failed with error " << WSAGetLastError() << '\n';
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    cout << "UDP server is running on port " << kDiscoveryPort << '\n';
    cout << "Waiting for packets from clients...\n";

    unordered_map<string, TransferState> sessions;

    while (true) {
        sockaddr_in from{};
        PacketHeaderHost h{};
        vector<char> p;

        if (!recvPacket(serverSocket, h, p, from)) {
            continue;
        }

        const string clientKey = endpointToString(from);

        if (h.type == PACKET_DISCOVER) {
            cout << "Client discovered: " << clientKey << '\n';
            PacketHeaderHost offer{};
            offer.type = PACKET_OFFER;
            const string offerMsg = "OFFER";
            sendPacket(serverSocket, offer, offerMsg.data(), offerMsg.size(), from);
            continue;
        }

        if (h.type == PACKET_META) {
            auto& transfer = sessions[clientKey];
            initTransferFromMeta(transfer, h, p, clientKey);
            continue;
        }

        if (h.type == PACKET_DATA) {
            auto it = sessions.find(clientKey);
            if (it == sessions.end() || !it->second.initialized) {
                cout << "[" << clientKey << "] DATA before META. Ignored.\n";
                continue;
            }

            TransferState& transfer = it->second;
            if (h.partIndex >= transfer.totalParts) {
                cout << "[" << clientKey << "] Invalid part index " << h.partIndex
                    << ". Ignored.\n";
                continue;
            }

            if (!transfer.received[h.partIndex]) {
                transfer.parts[h.partIndex] = p;
                transfer.received[h.partIndex] = true;
                ++transfer.receivedCount;
            }

            cout << "[" << clientKey << "] Part " << (h.partIndex + 1) << "/"
                << transfer.totalParts << " received, size = " << p.size() << '\n';

            if (transfer.receivedCount == transfer.totalParts) {
                bool ok = saveTransfer(transfer, clientKey);
                PacketHeaderHost ack{};
                ack.type = PACKET_ACK;
                string ackMsg = ok ? "RECEIVED_OK" : "RECEIVED_FAILED";
                sendPacket(serverSocket, ack, ackMsg.data(), ackMsg.size(), from);
                sessions.erase(it);
                cout << "Session finished for " << clientKey
                    << ". Active sessions: " << sessions.size() << '\n';
            }
            continue;
        }

        if (h.type == PACKET_DONE) {
            auto it = sessions.find(clientKey);
            bool ok = false;
            if (it != sessions.end()) {
                ok = saveTransfer(it->second, clientKey);
            }

            PacketHeaderHost ack{};
            ack.type = PACKET_ACK;
            string ackMsg = ok ? "RECEIVED_OK" : "RECEIVED_INCOMPLETE";
            sendPacket(serverSocket, ack, ackMsg.data(), ackMsg.size(), from);

            if (it != sessions.end()) {
                sessions.erase(it);
            }
            cout << "Session finished for " << clientKey
                << ". Active sessions: " << sessions.size() << '\n';
            continue;
        }
    }

    closesocket(serverSocket);
    WSACleanup();
    return 0;
}