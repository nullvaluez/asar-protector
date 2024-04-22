#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <napi.h>
#include <string>
#include <vector>

std::vector<unsigned char> deriveKey(const std::string& password, const std::vector<unsigned char>& salt, size_t keySize);
std::vector<unsigned char> encryptAES(const std::vector<unsigned char>& data, const std::string& password);
std::vector<unsigned char> encryptChaCha20(const std::vector<unsigned char>& data, const std::string& password);
std::vector<unsigned char> encryptData(const std::vector<unsigned char>& data, const std::string& password);

#endif