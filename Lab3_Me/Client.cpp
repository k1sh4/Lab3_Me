#include <winsock2.h>
#include <ws2tcpip.h>
#include <shellapi.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Shell32.lib")

using namespace std;

namespace {
    constexpr uint16_t kDiscoveryPortDefault = 5001;
    constexpr uint32_t kMagic = 0x4C414233;  // "LAB3"
    constexpr int kMaxDatagramBytes = 60000;
    constexpr const char* kDefaultFileName = "test.rtf";
    constexpr int kDefaultMode = 2;
    constexpr int kDefaultRecordBookLast2 = 47; //залікова
    constexpr const char* kDefaultServerIpDebug = "127.0.0.1";
    constexpr int kDefaultClientsCount = 1;

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

    string getFileNameOnly(const string& path) {
        size_t p = path.find_last_of("\\/");
        if (p == string::npos) {
            return path;
        }
        return path.substr(p + 1);
    }

    bool isRtfFile(const string& path) {
        string lower = path;
        transform(lower.begin(), lower.end(), lower.begin(),
            [](unsigned char c) { return static_cast<char>(tolower(c)); });
        return lower.size() >= 4 && lower.substr(lower.size() - 4) == ".rtf";
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
            return false;
        }

        if (received < static_cast<int>(sizeof(PacketHeaderNet))) {
            return false;
        }

        PacketHeaderNet netHeader{};
        memcpy(&netHeader, raw.data(), sizeof(netHeader));
        header = toHost(netHeader);

        if (header.magic != kMagic) {
            return false;
        }

        int availablePayload = received - static_cast<int>(sizeof(PacketHeaderNet));
        if (header.payloadSize > static_cast<uint32_t>(availablePayload)) {
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

    bool tryOpenFile(const string& path, vector<char>& data) {
        ifstream in(path, ios::binary);
        if (!in.is_open()) {
            return false;
        }
        data.assign((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
        in.close();
        return true;
    }

    bool tryLoadFileForVisualStudio(const string& requestedPath, vector<char>& data,
        string& resolvedPath) {
        const vector<string> candidates = {
            requestedPath,
            ".\\" + requestedPath,
            "..\\" + requestedPath,
            "..\\..\\" + requestedPath,
            "..\\..\\..\\" + requestedPath
        };

        for (const auto& candidate : candidates) {
            if (tryOpenFile(candidate, data)) {
                resolvedPath = candidate;
                return true;
            }
        }

        return false;
    }

    void printUsage() {
        cout << "Usage:\n";
        cout << "  Client.exe <file.rtf> <mode 1|2> <record_book_last2digits>"
            " [broadcast_ip] [port] [clients_count]\n";
    }

    bool runClientSession(int clientId, const string& fileNameOnly, const vector<char>& fileData,
        uint32_t fileSize, uint32_t totalParts, int mode, const string& broadcastIp,
        uint16_t discoveryPort, mutex& logMutex) {
        auto log = [&](const string& text) {
            lock_guard<mutex> lock(logMutex);
            cout << "[Client " << clientId << "] " << text << '\n';
            };

        SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET) {
            log("socket() failed");
            return false;
        }

        BOOL broadcastEnable = TRUE;
        setsockopt(sock, SOL_SOCKET, SO_BROADCAST, reinterpret_cast<const char*>(&broadcastEnable),
            sizeof(broadcastEnable));

        int timeoutMs = 5000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeoutMs),
            sizeof(timeoutMs));

        sockaddr_in broadcastAddr{};
        broadcastAddr.sin_family = AF_INET;
        broadcastAddr.sin_port = htons(discoveryPort);
        if (InetPtonA(AF_INET, broadcastIp.c_str(), &broadcastAddr.sin_addr) != 1) {
            log("Invalid broadcast IP");
            closesocket(sock);
            return false;
        }

        PacketHeaderHost discover{};
        discover.type = PACKET_DISCOVER;
        const string discoverMsg = "DISCOVER";
        if (!sendPacket(sock, discover, discoverMsg.data(), discoverMsg.size(), broadcastAddr)) {
            log("Failed to send DISCOVER packet");
            closesocket(sock);
            return false;
        }
        log("DISCOVER sent to " + broadcastIp + ":" + to_string(discoveryPort));

        sockaddr_in serverAddr{};
        PacketHeaderHost answer{};
        vector<char> answerPayload;
        if (!recvPacket(sock, answer, answerPayload, serverAddr) || answer.type != PACKET_OFFER) {
            log("Server OFFER not received (timeout or invalid response)");
            closesocket(sock);
            return false;
        }

        log("OFFER received. Server selected.");

        PacketHeaderHost meta{};
        meta.type = PACKET_META;
        meta.mode = static_cast<uint32_t>(mode);
        meta.totalParts = totalParts;
        meta.fileSize = fileSize;
        if (!sendPacket(sock, meta, fileNameOnly.data(), fileNameOnly.size(), serverAddr)) {
            log("Failed to send META packet");
            closesocket(sock);
            return false;
        }

        log("Sending file: " + fileNameOnly + ", bytes: " + to_string(fileSize) +
            ", mode: " + to_string(mode) + ", parts: " + to_string(totalParts));

        for (uint32_t i = 0; i < totalParts; ++i) {
            uint32_t start = static_cast<uint32_t>((static_cast<uint64_t>(fileSize) * i) / totalParts);
            uint32_t end =
                static_cast<uint32_t>((static_cast<uint64_t>(fileSize) * (i + 1)) / totalParts);
            uint32_t chunk = end - start;

            PacketHeaderHost data{};
            data.type = PACKET_DATA;
            data.mode = static_cast<uint32_t>(mode);
            data.totalParts = totalParts;
            data.partIndex = i;
            data.fileSize = fileSize;

            const char* chunkPtr = (chunk > 0) ? (fileData.data() + start) : nullptr;
            if (!sendPacket(sock, data, chunkPtr, chunk, serverAddr)) {
                log("Failed to send DATA packet for fragment " + to_string(i + 1));
                closesocket(sock);
                return false;
            }
        }

        PacketHeaderHost done{};
        done.type = PACKET_DONE;
        done.mode = static_cast<uint32_t>(mode);
        done.totalParts = totalParts;
        done.fileSize = fileSize;
        sendPacket(sock, done, nullptr, 0, serverAddr);

        PacketHeaderHost ack{};
        vector<char> ackPayload;
        sockaddr_in ackFrom{};
        bool ok = false;
        if (recvPacket(sock, ack, ackPayload, ackFrom) && ack.type == PACKET_ACK) {
            string ackText(ackPayload.begin(), ackPayload.end());
            log("Server ACK: " + ackText);
            ok = (ackText == "RECEIVED_OK");
        }
        else {
            log("ACK not received. UDP delivery is not guaranteed.");
        }

        closesocket(sock);
        return ok;
    }
}  // namespace

int main(int argc, char* argv[]) {
    string filePath;
    int mode = kDefaultMode;
    int recordBookLast2 = kDefaultRecordBookLast2;
    string broadcastIp = kDefaultServerIpDebug;
    uint16_t discoveryPort = kDiscoveryPortDefault;
    int clientsCount = kDefaultClientsCount;
    bool launchedWithDefaults = false;

    if (argc < 4) {
        launchedWithDefaults = true;
        filePath = kDefaultFileName;
        cout << "No command arguments provided.\n";
        cout << "Using defaults for Visual Studio debug run:\n";
        cout << "  file = " << filePath << ", mode = " << mode
            << ", record_book_last2digits = " << recordBookLast2
            << ", ip = " << broadcastIp << ", port = " << discoveryPort
            << ", clients_count = " << clientsCount << "\n\n";
        printUsage();
        cout << '\n';
    }
    else {
        filePath = argv[1];
        mode = atoi(argv[2]);
        recordBookLast2 = atoi(argv[3]);
        broadcastIp = (argc >= 5) ? argv[4] : "255.255.255.255";
        discoveryPort = (argc >= 6) ? static_cast<uint16_t>(atoi(argv[5])) : kDiscoveryPortDefault;
        clientsCount = (argc >= 7) ? atoi(argv[6]) : kDefaultClientsCount;
    }

    if (mode != 1 && mode != 2) {
        cout << "Mode must be 1 or 2\n";
        return 1;
    }

    if (clientsCount < 1) {
        cout << "clients_count must be >= 1\n";
        return 1;
    }

    if (!isRtfFile(filePath)) {
        cout << "Warning: lab variant expects .rtf file\n";
    }

    vector<char> fileData;
    string resolvedPath;
    if (!tryLoadFileForVisualStudio(filePath, fileData, resolvedPath)) {
        cout << "Cannot open input file: " << filePath << '\n';
        cout << "Tip: put file near .exe or set Working Directory = $(ProjectDir)\n";
        return 1;
    }
    if (launchedWithDefaults) {
        cout << "Input file found at: " << resolvedPath << '\n';
    }

    const uint32_t fileSize = static_cast<uint32_t>(fileData.size());
    uint32_t totalParts = (mode == 1) ? 1u : static_cast<uint32_t>(max(1, recordBookLast2));

    const size_t maxDataBytes = static_cast<size_t>(kMaxDatagramBytes - sizeof(PacketHeaderNet));
    if (mode == 1 && fileData.size() > maxDataBytes) {
        cout << "File is too big for mode 1 (single UDP datagram). Use mode 2.\n";
        return 1;
    }

    // Check if any fragment in mode 2 exceeds UDP datagram payload limit.
    for (uint32_t i = 0; i < totalParts; ++i) {
        uint32_t start = static_cast<uint32_t>((static_cast<uint64_t>(fileSize) * i) / totalParts);
        uint32_t end =
            static_cast<uint32_t>((static_cast<uint64_t>(fileSize) * (i + 1)) / totalParts);
        uint32_t chunk = end - start;
        if (chunk > maxDataBytes) {
            cout << "Fragment " << (i + 1) << " is too large for UDP. Increase fragment count.\n";
            return 1;
        }
    }

    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        cout << "WSAStartup failed\n";
        return 1;
    }

    const string fileNameOnly = getFileNameOnly(filePath);
    mutex logMutex;
    vector<int> sessionResults(static_cast<size_t>(clientsCount), 0);
    vector<thread> workers;
    workers.reserve(static_cast<size_t>(clientsCount));

    cout << "Launching " << clientsCount << " client(s)...\n";
    for (int i = 0; i < clientsCount; ++i) {
        workers.emplace_back([&, i]() {
            sessionResults[static_cast<size_t>(i)] =
                runClientSession(i + 1, fileNameOnly, fileData, fileSize, totalParts, mode,
                    broadcastIp, discoveryPort, logMutex)
                ? 1
                : 0;
            });
    }

    for (auto& worker : workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }

    int successCount = 0;
    for (int ok : sessionResults) {
        if (ok) {
            ++successCount;
        }
    }

    cout << "Completed: " << successCount << "/" << clientsCount
        << " client(s) received RECEIVED_OK ACK.\n";

    if (clientsCount == 1 && successCount == 1) {
        openTextFile(resolvedPath);
    }

    WSACleanup();
    return (successCount > 0) ? 0 : 1;
}