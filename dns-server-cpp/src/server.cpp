#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <vector>
#include <cstdint>
#include <set>
#include <arpa/inet.h>
#include <string>

// DNS Header structure (12 bytes)
struct DNSHeader {
    uint16_t id;          // Identification number
    uint16_t flags;       // DNS flags
    uint16_t qdcount;     // Number of questions
    uint16_t ancount;     // Number of answers
    uint16_t nscount;     // Number of authority records
    uint16_t arcount;     // Number of additional records
};

// DNS Question structure
struct DNSQuestion {
    std::vector<uint8_t> name;  // Uncompressed domain name
    uint16_t qtype;             // Question type
    uint16_t qclass;            // Question class
};

// DNS Message class to handle parsing and creation
class DNSMessage {
public:
    DNSHeader header;
    std::vector<uint8_t> rawData;
    std::vector<DNSQuestion> questions;  // All parsed questions

    // Parse incoming DNS query
    bool parseFromBuffer(const char* buffer, int length) {
        if (length < 12) return false; // Need at least header

        rawData.assign(buffer, buffer + length);

        // Parse header (network byte order)
        header.id = ntohs(*reinterpret_cast<const uint16_t*>(buffer));
        header.flags = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 2));
        header.qdcount = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 4));
        header.ancount = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 6));
        header.nscount = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 8));
        header.arcount = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 10));

        // Parse all questions
        if (header.qdcount > 0 && length > 12) {
            return parseAllQuestions();
        }

        return true;
    }

private:
    // Parse all questions from the question section
    bool parseAllQuestions() {
        questions.clear();
        int offset = 12; // Start after header

        for (int i = 0; i < header.qdcount; i++) {
            DNSQuestion question;

            // Parse domain name (with compression support)
            if (!parseDomainName(offset, question.name)) {
                return false;
            }

            // Parse type and class (4 bytes total)
            if (offset + 4 > rawData.size()) return false;

            question.qtype = ntohs(*reinterpret_cast<const uint16_t*>(&rawData[offset]));
            offset += 2;
            question.qclass = ntohs(*reinterpret_cast<const uint16_t*>(&rawData[offset]));
            offset += 2;

            questions.push_back(question);
        }

        return true;
    }

    // Parse domain name with DNS compression support
    bool parseDomainName(int& offset, std::vector<uint8_t>& name) {
        name.clear();
        std::set<int> visitedOffsets; // Prevent infinite loops

        while (offset < rawData.size()) {
            uint8_t labelLength = rawData[offset];

            // Check for compression pointer (top 2 bits = 11)
            if ((labelLength & 0xC0) == 0xC0) {
                // This is a compression pointer
                if (offset + 1 >= rawData.size()) return false;

                int pointerOffset = ((labelLength & 0x3F) << 8) | rawData[offset + 1];
                offset += 2; // Move past the pointer

                // Prevent infinite loops
                if (visitedOffsets.count(pointerOffset)) return false;
                visitedOffsets.insert(pointerOffset);

                // Follow the pointer to decompress
                std::vector<uint8_t> compressedPart;
                int tempOffset = pointerOffset;
                if (!parseDomainNameRecursive(tempOffset, compressedPart, visitedOffsets)) {
                    return false;
                }

                // Append the decompressed part (without null terminator if present)
                if (!compressedPart.empty() && compressedPart.back() == 0x00) {
                    compressedPart.pop_back();
                }
                name.insert(name.end(), compressedPart.begin(), compressedPart.end());
                name.push_back(0x00); // Add null terminator
                return true;
            }

            if (labelLength == 0) {
                // End of domain name
                name.push_back(0x00);
                offset++;
                return true;
            }

            // Regular label
            if (offset + 1 + labelLength > rawData.size()) return false;

            name.push_back(labelLength);
            offset++;

            for (int i = 0; i < labelLength; i++) {
                name.push_back(rawData[offset]);
                offset++;
            }
        }

        return false; // Shouldn't reach here for valid DNS names
    }

    // Recursive helper for parsing compressed domain names
    bool parseDomainNameRecursive(int& offset, std::vector<uint8_t>& name, std::set<int>& visitedOffsets) {
        while (offset < rawData.size()) {
            uint8_t labelLength = rawData[offset];

            if ((labelLength & 0xC0) == 0xC0) {
                // Another compression pointer
                if (offset + 1 >= rawData.size()) return false;

                int pointerOffset = ((labelLength & 0x3F) << 8) | rawData[offset + 1];

                if (visitedOffsets.count(pointerOffset)) return false;
                visitedOffsets.insert(pointerOffset);

                offset = pointerOffset;
                continue;
            }

            if (labelLength == 0) {
                name.push_back(0x00);
                return true;
            }

            // Regular label
            if (offset + 1 + labelLength > rawData.size()) return false;

            name.push_back(labelLength);
            offset++;

            for (int i = 0; i < labelLength; i++) {
                name.push_back(rawData[offset]);
                offset++;
            }
        }

        return false;
    }

public:

    // Create DNS response
    std::vector<uint8_t> createResponse() {
        std::vector<uint8_t> response;

        // Create response header
        DNSHeader responseHeader = header;

        // Extract fields from request flags
        uint16_t requestFlags = header.flags;
        uint16_t opcode = (requestFlags >> 11) & 0x0F;  // Extract OPCODE (bits 14-11)
        uint16_t rd = (requestFlags >> 8) & 0x01;       // Extract RD (bit 8)

        // Build response flags
        uint16_t responseFlags = 0;
        responseFlags |= (1 << 15);        // QR = 1 (response)
        responseFlags |= (opcode << 11);   // OPCODE = mimic request
        responseFlags |= (rd << 8);        // RD = mimic request (bit 8)

        // RCODE (bits 3-0): 0 if OPCODE=0, else 4
        uint16_t rcode = (opcode == 0) ? 0 : 4;
        responseFlags |= rcode;

        responseHeader.flags = responseFlags;

        // Set ANCOUNT to match number of questions (one answer per question)
        responseHeader.ancount = questions.size();

        // Convert header to network byte order
        uint16_t netId = htons(responseHeader.id);
        uint16_t netFlags = htons(responseHeader.flags);
        uint16_t netQdcount = htons(responseHeader.qdcount);
        uint16_t netAncount = htons(responseHeader.ancount);
        uint16_t netNscount = htons(responseHeader.nscount);
        uint16_t netArcount = htons(responseHeader.arcount);

        // Add header to response
        response.insert(response.end(), reinterpret_cast<uint8_t*>(&netId), reinterpret_cast<uint8_t*>(&netId) + 2);
        response.insert(response.end(), reinterpret_cast<uint8_t*>(&netFlags), reinterpret_cast<uint8_t*>(&netFlags) + 2);
        response.insert(response.end(), reinterpret_cast<uint8_t*>(&netQdcount), reinterpret_cast<uint8_t*>(&netQdcount) + 2);
        response.insert(response.end(), reinterpret_cast<uint8_t*>(&netAncount), reinterpret_cast<uint8_t*>(&netAncount) + 2);
        response.insert(response.end(), reinterpret_cast<uint8_t*>(&netNscount), reinterpret_cast<uint8_t*>(&netNscount) + 2);
        response.insert(response.end(), reinterpret_cast<uint8_t*>(&netArcount), reinterpret_cast<uint8_t*>(&netArcount) + 2);

        // Add Question Section (uncompressed)
        for (const auto& question : questions) {
            // Add domain name (uncompressed)
            response.insert(response.end(), question.name.begin(), question.name.end());

            // Add type and class
            uint16_t netType = htons(question.qtype);
            uint16_t netClass = htons(question.qclass);
            response.insert(response.end(), reinterpret_cast<uint8_t*>(&netType), reinterpret_cast<uint8_t*>(&netType) + 2);
            response.insert(response.end(), reinterpret_cast<uint8_t*>(&netClass), reinterpret_cast<uint8_t*>(&netClass) + 2);
        }

        // Add Answer Section (one answer per question)
        for (size_t i = 0; i < questions.size(); i++) {
            const auto& question = questions[i];

            // Answer name (same as question name, uncompressed)
            response.insert(response.end(), question.name.begin(), question.name.end());

            // Type: A record (1) - 2 bytes big-endian
            uint16_t netType = htons(1);
            response.insert(response.end(), reinterpret_cast<uint8_t*>(&netType), reinterpret_cast<uint8_t*>(&netType) + 2);

            // Class: IN (1) - 2 bytes big-endian
            uint16_t netClass = htons(1);
            response.insert(response.end(), reinterpret_cast<uint8_t*>(&netClass), reinterpret_cast<uint8_t*>(&netClass) + 2);

            // TTL: 60 seconds - 4 bytes big-endian
            uint32_t netTTL = htonl(60);
            response.insert(response.end(), reinterpret_cast<uint8_t*>(&netTTL), reinterpret_cast<uint8_t*>(&netTTL) + 4);

            // Length: 4 (length of IP address) - 2 bytes big-endian
            uint16_t netLength = htons(4);
            response.insert(response.end(), reinterpret_cast<uint8_t*>(&netLength), reinterpret_cast<uint8_t*>(&netLength) + 2);

            // Data: Different IP addresses for variety
            // Use different IPs for each answer: 8.8.8.8, 1.1.1.1, 9.9.9.9, etc.
            std::vector<uint8_t> ipAddress;
            switch (i % 3) {
                case 0: ipAddress = {0x08, 0x08, 0x08, 0x08}; break; // 8.8.8.8
                case 1: ipAddress = {0x01, 0x01, 0x01, 0x01}; break; // 1.1.1.1
                case 2: ipAddress = {0x09, 0x09, 0x09, 0x09}; break; // 9.9.9.9
            }
            response.insert(response.end(), ipAddress.begin(), ipAddress.end());
        }

        return response;
    }
};

// Helper function to parse IP:port from resolver argument
bool parseResolverAddress(const std::string& address, std::string& ip, int& port) {
    size_t colonPos = address.find(':');
    if (colonPos == std::string::npos) {
        return false;
    }

    ip = address.substr(0, colonPos);
    std::string portStr = address.substr(colonPos + 1);

    try {
        port = std::stoi(portStr);
        return port > 0 && port <= 65535;
    } catch (...) {
        return false;
    }
}

// Forward DNS query to resolver and get response
std::vector<uint8_t> forwardDNSQuery(const std::vector<uint8_t>& query,
                                     const std::string& resolverIP,
                                     int resolverPort) {
    int forwarderSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (forwarderSocket == -1) {
        std::cerr << "Failed to create forwarder socket" << std::endl;
        return {};
    }

    // Set timeout for receive
    struct timeval timeout;
    timeout.tv_sec = 5;  // 5 second timeout
    timeout.tv_usec = 0;
    setsockopt(forwarderSocket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    sockaddr_in resolverAddr;
    resolverAddr.sin_family = AF_INET;
    resolverAddr.sin_port = htons(resolverPort);
    if (inet_pton(AF_INET, resolverIP.c_str(), &resolverAddr.sin_addr) <= 0) {
        std::cerr << "Invalid resolver IP address: " << resolverIP << std::endl;
        close(forwarderSocket);
        return {};
    }

    // Send query to resolver
    if (sendto(forwarderSocket, query.data(), query.size(), 0,
               reinterpret_cast<struct sockaddr*>(&resolverAddr), sizeof(resolverAddr)) == -1) {
        perror("Failed to forward DNS query");
        close(forwarderSocket);
        return {};
    }

    // Receive response from resolver
    char responseBuffer[512];
    int responseSize = recvfrom(forwarderSocket, responseBuffer, sizeof(responseBuffer), 0, nullptr, nullptr);

    close(forwarderSocket);

    if (responseSize == -1) {
        perror("Failed to receive DNS response");
        return {};
    }

    std::vector<uint8_t> response(responseBuffer, responseBuffer + responseSize);
    return response;
}

// Create single question DNS query packet
std::vector<uint8_t> createSingleQuestionQuery(const DNSMessage& originalMessage, int questionIndex) {
    std::vector<uint8_t> query;

    // Create header for single question
    DNSHeader queryHeader = originalMessage.header;
    queryHeader.qdcount = 1;  // Only one question
    queryHeader.ancount = 0;  // No answers in query
    queryHeader.nscount = 0;
    queryHeader.arcount = 0;

    // Convert header to network byte order
    uint16_t netId = htons(queryHeader.id);
    uint16_t netFlags = htons(queryHeader.flags);
    uint16_t netQdcount = htons(queryHeader.qdcount);
    uint16_t netAncount = htons(queryHeader.ancount);
    uint16_t netNscount = htons(queryHeader.nscount);
    uint16_t netArcount = htons(queryHeader.arcount);

    // Add header
    query.insert(query.end(), reinterpret_cast<uint8_t*>(&netId), reinterpret_cast<uint8_t*>(&netId) + 2);
    query.insert(query.end(), reinterpret_cast<uint8_t*>(&netFlags), reinterpret_cast<uint8_t*>(&netFlags) + 2);
    query.insert(query.end(), reinterpret_cast<uint8_t*>(&netQdcount), reinterpret_cast<uint8_t*>(&netQdcount) + 2);
    query.insert(query.end(), reinterpret_cast<uint8_t*>(&netAncount), reinterpret_cast<uint8_t*>(&netAncount) + 2);
    query.insert(query.end(), reinterpret_cast<uint8_t*>(&netNscount), reinterpret_cast<uint8_t*>(&netNscount) + 2);
    query.insert(query.end(), reinterpret_cast<uint8_t*>(&netArcount), reinterpret_cast<uint8_t*>(&netArcount) + 2);

    // Add single question
    const DNSQuestion& question = originalMessage.questions[questionIndex];
    query.insert(query.end(), question.name.begin(), question.name.end());

    uint16_t netType = htons(question.qtype);
    uint16_t netClass = htons(question.qclass);
    query.insert(query.end(), reinterpret_cast<uint8_t*>(&netType), reinterpret_cast<uint8_t*>(&netType) + 2);
    query.insert(query.end(), reinterpret_cast<uint8_t*>(&netClass), reinterpret_cast<uint8_t*>(&netClass) + 2);

    return query;
}

// Build merged response from resolver responses
std::vector<uint8_t> buildMergedResponse(const DNSMessage& originalMessage,
                                        const std::vector<std::vector<uint8_t>>& resolverResponses) {
    std::vector<uint8_t> response;

    // Create response header matching the original request
    DNSHeader responseHeader = originalMessage.header;

    // Extract fields from original request flags
    uint16_t requestFlags = originalMessage.header.flags;
    uint16_t opcode = (requestFlags >> 11) & 0x0F;  // Extract OPCODE
    uint16_t rd = (requestFlags >> 8) & 0x01;       // Extract RD

    // Build response flags
    uint16_t responseFlags = 0;
    responseFlags |= (1 << 15);        // QR = 1 (response)
    responseFlags |= (opcode << 11);   // OPCODE = mimic request
    responseFlags |= (rd << 8);        // RD = mimic request

    // RCODE: 0 if OPCODE=0, else 4
    uint16_t rcode = (opcode == 0) ? 0 : 4;
    responseFlags |= rcode;

    responseHeader.flags = responseFlags;
    responseHeader.ancount = 0;  // Will count valid answers

    // Count valid answers
    for (const auto& resolverResponse : resolverResponses) {
        if (!resolverResponse.empty() && resolverResponse.size() >= 12) {
            // Parse the resolver response to get answer count
            uint16_t answerCount = ntohs(*reinterpret_cast<const uint16_t*>(&resolverResponse[6]));
            responseHeader.ancount += answerCount;
        }
    }

    // Convert header to network byte order
    uint16_t netId = htons(responseHeader.id);
    uint16_t netFlags = htons(responseHeader.flags);
    uint16_t netQdcount = htons(responseHeader.qdcount);
    uint16_t netAncount = htons(responseHeader.ancount);
    uint16_t netNscount = htons(responseHeader.nscount);
    uint16_t netArcount = htons(responseHeader.arcount);

    // Add header
    response.insert(response.end(), reinterpret_cast<uint8_t*>(&netId), reinterpret_cast<uint8_t*>(&netId) + 2);
    response.insert(response.end(), reinterpret_cast<uint8_t*>(&netFlags), reinterpret_cast<uint8_t*>(&netFlags) + 2);
    response.insert(response.end(), reinterpret_cast<uint8_t*>(&netQdcount), reinterpret_cast<uint8_t*>(&netQdcount) + 2);
    response.insert(response.end(), reinterpret_cast<uint8_t*>(&netAncount), reinterpret_cast<uint8_t*>(&netAncount) + 2);
    response.insert(response.end(), reinterpret_cast<uint8_t*>(&netNscount), reinterpret_cast<uint8_t*>(&netNscount) + 2);
    response.insert(response.end(), reinterpret_cast<uint8_t*>(&netArcount), reinterpret_cast<uint8_t*>(&netArcount) + 2);

    // Add all questions from original request
    for (const auto& question : originalMessage.questions) {
        response.insert(response.end(), question.name.begin(), question.name.end());
        uint16_t netType = htons(question.qtype);
        uint16_t netClass = htons(question.qclass);
        response.insert(response.end(), reinterpret_cast<uint8_t*>(&netType), reinterpret_cast<uint8_t*>(&netType) + 2);
        response.insert(response.end(), reinterpret_cast<uint8_t*>(&netClass), reinterpret_cast<uint8_t*>(&netClass) + 2);
    }

    // Extract and add answer sections from each resolver response
    for (size_t i = 0; i < resolverResponses.size(); i++) {
        const auto& resolverResponse = resolverResponses[i];

        if (resolverResponse.empty() || resolverResponse.size() < 12) {
            continue; // Skip empty or invalid responses
        }

        // Parse resolver response header
        uint16_t resolverQdcount = ntohs(*reinterpret_cast<const uint16_t*>(&resolverResponse[4]));
        uint16_t resolverAncount = ntohs(*reinterpret_cast<const uint16_t*>(&resolverResponse[6]));

        if (resolverAncount == 0) {
            continue; // No answers in this response
        }

        // Find start of answer section by skipping header + question section
        int offset = 12; // Skip header

        // Skip question section in resolver response
        for (int q = 0; q < resolverQdcount; q++) {
            // Skip domain name
            while (offset < resolverResponse.size()) {
                uint8_t len = resolverResponse[offset];
                if (len == 0) {
                    offset++; // Skip null terminator
                    break;
                }
                if ((len & 0xC0) == 0xC0) {
                    offset += 2; // Skip compression pointer
                    break;
                }
                offset += 1 + len; // Skip length + label
            }
            offset += 4; // Skip type and class
        }

        // Copy answer section
        if (offset < resolverResponse.size()) {
            response.insert(response.end(), resolverResponse.begin() + offset, resolverResponse.end());
        }
    }

    return response;
}

int main(int argc, char* argv[]) {
    // Flush after every std::cout / std::cerr
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;
    setbuf(stdout, NULL);

    // Parse command line arguments
    std::string resolverIP;
    int resolverPort;
    bool useResolver = false;

    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "--resolver" && i + 1 < argc) {
            if (parseResolverAddress(argv[i + 1], resolverIP, resolverPort)) {
                useResolver = true;
                std::cout << "Using resolver: " << resolverIP << ":" << resolverPort << std::endl;
            } else {
                std::cerr << "Invalid resolver address format. Expected IP:PORT" << std::endl;
                return 1;
            }
            i++; // Skip the next argument as it's the address
        }
    }

    // Create UDP socket
    int udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSocket == -1) {
        std::cerr << "Socket creation failed: " << strerror(errno) << std::endl;
        return 1;
    }

    int reuse = 1;
    if (setsockopt(udpSocket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
        std::cerr << "SO_REUSEPORT failed: " << strerror(errno) << std::endl;
        return 1;
    }

    sockaddr_in serv_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(2053),
        .sin_addr = { htonl(INADDR_ANY) },
    };

    if (bind(udpSocket, reinterpret_cast<struct sockaddr*>(&serv_addr), sizeof(serv_addr)) != 0) {
        std::cerr << "Bind failed: " << strerror(errno) << std::endl;
        return 1;
    }

    std::cout << "DNS server listening on port 2053..." << std::endl;

    int bytesRead;
    char buffer[512];
    sockaddr_in clientAddress;
    socklen_t clientAddrLen = sizeof(clientAddress);

    while (true) {
        bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0,
                           reinterpret_cast<struct sockaddr*>(&clientAddress), &clientAddrLen);
        if (bytesRead == -1) {
            perror("Error receiving data");
            break;
        }

        std::cout << "Received " << bytesRead << " bytes of DNS data" << std::endl;

        DNSMessage dnsMessage;
        if (!dnsMessage.parseFromBuffer(buffer, bytesRead)) {
            std::cerr << "Failed to parse DNS message" << std::endl;
            continue;
        }

        std::cout << "DNS Query - ID: " << dnsMessage.header.id
                  << ", Questions: " << dnsMessage.header.qdcount << std::endl;

        std::vector<uint8_t> response;

        if (useResolver && !dnsMessage.questions.empty()) {
            // Forward to resolver - handle single or multiple questions
            std::vector<std::vector<uint8_t>> resolverResponses;

            // Send each question separately to resolver
            for (size_t i = 0; i < dnsMessage.questions.size(); i++) {
                std::cout << "Forwarding question " << (i+1) << " to resolver..." << std::endl;

                std::vector<uint8_t> singleQuery = createSingleQuestionQuery(dnsMessage, i);
                std::vector<uint8_t> resolverResponse = forwardDNSQuery(singleQuery, resolverIP, resolverPort);

                if (!resolverResponse.empty()) {
                    resolverResponses.push_back(resolverResponse);
                } else {
                    std::cerr << "Failed to get response for question " << (i+1) << std::endl;
                    // Create empty response to maintain question/answer alignment
                    resolverResponses.push_back({});
                }
            }

            // Build merged response
            response = buildMergedResponse(dnsMessage, resolverResponses);

        } else {
            // Fallback to original behavior if no resolver specified
            response = dnsMessage.createResponse();
        }

        // Send response back to client
        if (sendto(udpSocket, response.data(), response.size(), 0,
                   reinterpret_cast<struct sockaddr*>(&clientAddress), sizeof(clientAddress)) == -1) {
            perror("Failed to send DNS response");
        } else {
            std::cout << "Sent DNS response of " << response.size() << " bytes" << std::endl;
        }
    }

    close(udpSocket);
    return 0;
}
