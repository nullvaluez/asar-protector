#include "utils.h"
#include <openssl/sha.h>

// Function to calculate SHA-256 checksum
std::string calculateChecksum(const std::vector<unsigned char>& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.data(), data.size());
    SHA256_Final(hash, &sha256);

    // Convert hash to hex string
    std::stringstream ss;
    for (unsigned char i : hash)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)i;

    return ss.str();
}

// Function to bloat data with random bytes
std::vector<unsigned char> bloatData(const std::vector<unsigned char>& data, size_t bloatSize) {
    std::vector<unsigned char> bloatedData(data);
    bloatedData.reserve(data.size() + bloatSize);

    // Generate random bytes and append to data
    for (size_t i = 0; i < bloatSize; ++i) {
        bloatedData.push_back(rand() % 256);
    }

    return bloatedData;
}