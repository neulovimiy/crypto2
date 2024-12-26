#include "rsa_generator.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <openssl/rand.h>
#include <algorithm> // Для std::min

void generateRSAKeys(const std::string& entropyData, const std::string& publicKeyFilename, const std::string& privateKeyFilename) {
    if (entropyData.empty()) {
        std::cerr << "Ошибка: недостаточно энтропии." << std::endl;
        return;
    }

    RAND_add(entropyData.data(), entropyData.size(), entropyData.size() * 0.5);

    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();

    // Use a fixed public exponent (65537)
    if (BN_set_word(bn, RSA_F4) != 1) {
        std::cerr << "Ошибка установки публичного экспонента." << std::endl;
        BN_free(bn);
        return;
    }

    // Generate RSA keys
    if (RSA_generate_key_ex(rsa, 2048, bn, NULL) != 1) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        std::cerr << "Ошибка генерации ключей: " << err_buf << std::endl;
        BN_free(bn);
        RSA_free(rsa);
        return;
    }

    // Save public key
    BIO *pub = BIO_new_file(publicKeyFilename.c_str(), "w");
    if (!PEM_write_bio_RSAPublicKey(pub, rsa)) {
        std::cerr << "Ошибка записи публичного ключа." << std::endl;
    }
    BIO_free_all(pub);

    // Save private key
    BIO *priv = BIO_new_file(privateKeyFilename.c_str(), "w");
    if (!PEM_write_bio_RSAPrivateKey(priv, rsa, NULL, NULL, 0, NULL, NULL)) {
        std::cerr << "Ошибка записи приватного ключа." << std::endl;
    }
    BIO_free_all(priv);

    BN_free(bn);
    RSA_free(rsa);
}

std::vector<unsigned char> rsaEncryptFile(const std::vector<unsigned char>& message, const std::string& publicKeyFilename) {
    FILE *fp = fopen(publicKeyFilename.c_str(), "r");
    if (fp == NULL) {
        std::cerr << "Ошибка открытия публичного ключа: " << publicKeyFilename << std::endl;
        return {};
    }

    RSA *rsa = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (rsa == NULL) {
        std::cerr << "Ошибка чтения публичного ключа" << std::endl;
        ERR_print_errors_fp(stderr);
        return {};
    }

    int blockSize = RSA_size(rsa) - 11; // Максимальный размер блока для шифрования
    std::vector<unsigned char> encryptedData;

    for (size_t i = 0; i < message.size(); i += blockSize) {
        size_t chunkSize = std::min(static_cast<size_t>(blockSize), message.size() - i);
        std::vector<unsigned char> chunk(message.begin() + i, message.begin() + i + chunkSize);

        std::vector<unsigned char> encryptedChunk(RSA_size(rsa));
        int encryptedLength = RSA_public_encrypt(chunk.size(), chunk.data(), encryptedChunk.data(), rsa, RSA_PKCS1_PADDING);
        if (encryptedLength == -1) {
            std::cerr << "Ошибка шифрования RSA" << std::endl;
            ERR_print_errors_fp(stderr);
            RSA_free(rsa);
            return {};
        }

        encryptedData.insert(encryptedData.end(), encryptedChunk.begin(), encryptedChunk.begin() + encryptedLength);
    }

    RSA_free(rsa);
    return encryptedData;
}

std::vector<unsigned char> rsaDecryptFile(const std::vector<unsigned char>& encryptedData, const std::string& privateKeyFilename) {
    FILE *fp = fopen(privateKeyFilename.c_str(), "r");
    if (fp == NULL) {
        std::cerr << "Ошибка открытия приватного ключа: " << privateKeyFilename << std::endl;
        return {};
    }

    RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (rsa == NULL) {
        std::cerr << "Ошибка чтения приватного ключа" << std::endl;
        ERR_print_errors_fp(stderr);
        return {};
    }

    int blockSize = RSA_size(rsa);
    std::vector<unsigned char> decryptedData;

    for (size_t i = 0; i < encryptedData.size(); i += blockSize) {
        std::vector<unsigned char> encryptedChunk(encryptedData.begin() + i, encryptedData.begin() + i + blockSize);

        std::vector<unsigned char> decryptedChunk(RSA_size(rsa));
        int decryptedLength = RSA_private_decrypt(encryptedChunk.size(), encryptedChunk.data(), decryptedChunk.data(), rsa, RSA_PKCS1_PADDING);
        if (decryptedLength == -1) {
            std::cerr << "Ошибка расшифровки RSA" << std::endl;
            ERR_print_errors_fp(stderr);
            RSA_free(rsa);
            return {};
        }

        decryptedData.insert(decryptedData.end(), decryptedChunk.begin(), decryptedChunk.begin() + decryptedLength);
    }

    RSA_free(rsa);
    return decryptedData;
}