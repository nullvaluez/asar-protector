#include <napi.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>

class EncryptWorker : public Napi::AsyncWorker {
public:
    EncryptWorker(Napi::Promise::Deferred deferred, const std::vector<unsigned char>& data, const std::string& password)
        : Napi::AsyncWorker(deferred.Env()), deferred_(deferred), data_(data), password_(password) {}

    void Execute() override {
        try {
            encryptedData_ = encryptData(data_, password_);
        } catch (const std::exception& e) {
            SetError(e.what());
        }
    }

    void OnOK() override {
        Napi::HandleScope scope(Env());
        deferred_.Resolve(Napi::Buffer<unsigned char>::Copy(Env(), encryptedData_.data(), encryptedData_.size()));
    }

private:
    Napi::Promise::Deferred deferred_;
    std::vector<unsigned char> data_;
    std::string password_;
    std::vector<unsigned char> encryptedData_;
};

std::vector<unsigned char> encryptData(const std::vector<unsigned char>& data, const std::string& password) {
    std::vector<unsigned char> salt(16);
    if (!RAND_bytes(salt.data(), salt.size())) {
        throw std::runtime_error("Failed to generate salt");
    }

    std::vector<unsigned char> key = deriveKey(password, salt, 32);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP cipher context");
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key.data(), NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize AES-256-GCM encryption");
    }

    std::vector<unsigned char> iv(12);
    if (!RAND_bytes(iv.data(), iv.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to generate IV");
    }

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set IV length for AES-256-GCM");
    }

    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to add IV for encryption");
    }

    std::vector<unsigned char> ciphertext(data.size() + EVP_CIPHER_CTX_block_size(ctx));
    int len;
    if (!EVP_EncryptUpdate(ctx, ciphertext.data(), &len, data.data(), data.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to encrypt data");
    }
    int ciphertext_len = len;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize encryption");
    }
    ciphertext_len += len;

    std::vector<unsigned char> tag(16);
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to get authentication tag");
    }

    std::vector<unsigned char> encryptedData;
    encryptedData.reserve(salt.size() + iv.size() + ciphertext_len + tag.size());
    encryptedData.insert(encryptedData.end(), salt.begin(), salt.end());
    encryptedData.insert(encryptedData.end(), iv.begin(), iv.end());
    encryptedData.insert(encryptedData.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);
    encryptedData.insert(encryptedData.end(), tag.begin(), tag.end());

    EVP_CIPHER_CTX_free(ctx);
    return encryptedData;
}

Napi::Value Encrypt(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 2 || !info[0].IsBuffer() || !info[1].IsString()) {
        Napi::TypeError::New(env, "Expected a Buffer and a string as arguments").ThrowAsJavaScriptException();
        return env.Null();
    }

    auto deferred = Napi::Promise::Deferred::New(env);
    auto worker = new EncryptWorker(deferred, Napi::Buffer<unsigned char>::Copy(env, info[0].As<Napi::Buffer<unsigned char>>().Data(), info[0].As<Napi::Buffer<unsigned char>>().Length()), info[1].As<Napi::String>().Utf8Value());
    worker->Queue();

    return deferred.Promise();
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set(Napi::String::New(env, "encrypt"), Napi::Function::New(env, Encrypt));
    // Additional registration omitted for brevity
    return exports;
}

NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init)
