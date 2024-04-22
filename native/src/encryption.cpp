#include "encryption.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <sodium.h>

// Function to derive encryption key using PBKDF2
std::vector<unsigned char> deriveKey(const std::string& password, const std::vector<unsigned char>& salt, size_t keySize) {
    std::vector<unsigned char> key(keySize);
    PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.size(), salt.data(), salt.size(), 10000, keySize, key.data());
    return key;
}

// Function to encrypt data using AES-256-GCM
std::vector<unsigned char> encryptAES(const std::vector<unsigned char>& data, const std::string& password) {
    // Generate random salt
    std::vector<unsigned char> salt(16);
    RAND_bytes(salt.data(), salt.size());

    // Derive encryption key
    std::vector<unsigned char> key = deriveKey(password, salt, 32);

    // Initialize cipher context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key.data(), NULL);

    // Set IV (we'll use a random IV for GCM)
    std::vector<unsigned char> iv(12);
    RAND_bytes(iv.data(), iv.size());
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv.data());

    // Encrypt data
    std::vector<unsigned char> ciphertext(data.size() + EVP_CIPHER_CTX_block_size(ctx));
    int len;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, data.data(), data.size());
    int ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;

    // Get tag
    std::vector<unsigned char> tag(16);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());

    // Combine salt, iv, ciphertext, and tag
    std::vector<unsigned char> encryptedData;
    encryptedData.insert(encryptedData.end(), salt.begin(), salt.end());
    encryptedData.insert(encryptedData.end(), iv.begin(), iv.end());
    encryptedData.insert(encryptedData.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);
    encryptedData.insert(encryptedData.end(), tag.begin(), tag.end());

    EVP_CIPHER_CTX_free(ctx);
    return encryptedData;
}

// Function to encrypt data using ChaCha20-Poly1305
std::vector<unsigned char> encryptChaCha20(const std::vector<unsigned char>& data, const std::string& password) {
    // Generate random nonce
    unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof nonce);

    // Derive key using Blake2b (recommended for ChaCha20)
    unsigned char key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    crypto_generichash(key, sizeof key, (const unsigned char*)password.c_str(), password.size(), NULL, 0);

    // Encrypt data
    std::vector<unsigned char> ciphertext(data.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long ciphertext_len;
    crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext.data(), &ciphertext_len,
        data.data(), data.size(),
        NULL, 0,
        NULL, nonce, key);

    // Combine nonce and ciphertext
    std::vector<unsigned char> encryptedData;
    encryptedData.insert(encryptedData.end(), nonce, nonce + sizeof nonce);
    encryptedData.insert(encryptedData.end(), ciphertext.begin(), ciphertext.end());

    return encryptedData;
}

// Function to perform polymorphic encryption
std::vector<unsigned char> encryptData(const std::vector<unsigned char>& data, const std::string& password) {
    // Choose a random encryption algorithm
    int algorithmChoice = rand() % 2; // 0 for AES, 1 for ChaCha20

    if (algorithmChoice == 0) {
        return encryptAES(data, password);
    }
    else {
        return encryptChaCha20(data, password);
    }
}

// Function to decrypt data (AES-256-GCM)
std::vector<unsigned char> decryptAES(const std::vector<unsigned char>& encryptedData, const std::string& password) {
    // using decryption operations
    const unsigned char* salt = encryptedData.data();
    const unsigned char* iv = salt + 16;
    const unsigned char* ciphertext = iv + 12;
    const unsigned char* tag = ciphertext + encryptedData.size() - 16;
    size_t ciphertext_len = encryptedData.size() - 16 - 12 - 16;
    std::vector<unsigned char> key = deriveKey(password, std::vector<unsigned char>(salt, salt + 16), 32);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key.data(), NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, iv);
    std::vector<unsigned char> plaintext(ciphertext_len);
    int len;
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, ciphertext_len);
    int plaintext_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag);
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    if (ret > 0) {
        plaintext_len += len;
        plaintext.resize(plaintext_len);
        return plaintext;
    }
    else {
        return std::vector<unsigned char>();
    }
}

// Function to decrypt data (ChaCha20-Poly1305) 
std::vector<unsigned char> decryptChaCha20(const std::vector<unsigned char>& encryptedData, const std::string& password) {
    const unsigned char* nonce = encryptedData.data();
    const unsigned char* ciphertext = nonce + crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    size_t ciphertext_len = encryptedData.size() - crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    unsigned char key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    crypto_generichash(key, sizeof key, (const unsigned char*)password.c_str(), password.size(), NULL, 0);
    std::vector<unsigned char> plaintext(ciphertext_len - crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long plaintext_len;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(plaintext.data(), &plaintext_len,
        NULL,
        ciphertext, ciphertext_len,
        NULL, 0,
        nonce, key) == 0) {
        plaintext.resize(plaintext_len);
        return plaintext;
    }
    else {
        return std::vector<unsigned char>();
    }
}

// Function to perform polymorphic decryption
std::vector<unsigned char> decryptData(const std::vector<unsigned char>& encryptedData, const std::string& password) {
    // Determine encryption algorithm based on data structure (e.g., check for nonce size)
    // For now, assume the first byte indicates the algorithm choice
    // 0: AES, 1: ChaCha20
    int algorithmChoice = encryptedData[0];

    if (algorithmChoice == 0) {
        // Call AES decryption function
        return decryptAES(std::vector<unsigned char>(encryptedData.begin() + 1, encryptedData.end()), password);
    }
    else {
        // Call ChaCha20 decryption function
        return decryptChaCha20(std::vector<unsigned char>(encryptedData.begin() + 1, encryptedData.end()), password);
    }
}