#include "aes_generator.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <fstream>
#include <iostream>

void generateAESKeys(const std::string& entropyData, const std::string& keyFile, const std::string& ivFile) {
    const int keyLength = 32; // 256 бит
    const int ivLength = 16;  // 128 бит

    unsigned char key[keyLength];
    unsigned char iv[ivLength];

    // Добавляем собранную энтропию в генератор случайных чисел
    RAND_add(entropyData.data(), entropyData.size(), 0.0);

    // Генерация случайных значений
    if (!RAND_bytes(key, keyLength) || !RAND_bytes(iv, ivLength)) {
        std::cerr << "Ошибка генерации ключа или IV." << std::endl;
        return;
    }

    // Сохранение ключа в файл
    std::ofstream keyOut(keyFile, std::ios::binary);
    if (!keyOut) {
        std::cerr << "Не удалось открыть файл для записи ключа: " << keyFile << std::endl;
        return;
    }
    keyOut.write((char*)key, keyLength);
    keyOut.close();

    // Сохранение IV в файл
    std::ofstream ivOut(ivFile, std::ios::binary);
    if (!ivOut) {
        std::cerr << "Не удалось открыть файл для записи IV: " << ivFile << std::endl;
        return;
    }
    ivOut.write((char*)iv, ivLength);
    ivOut.close();

    std::cout << "AES ключ сохранен в " << keyFile << ", IV сохранен в " << ivFile << std::endl;
}

std::vector<unsigned char> aesEncrypt(const std::string& plaintext, const std::string& keyFile) {
    std::ifstream file(keyFile, std::ios::binary);
    if (!file) {
        std::cerr << "Не удалось открыть файл с ключом." << std::endl;
        return {};
    }

    const int keyLength = 32;
    const int ivLength = 16;
    unsigned char key[keyLength];
    unsigned char iv[ivLength];

    file.read((char*)key, keyLength);
    file.read((char*)iv, ivLength);
    file.close();

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Ошибка создания контекста шифрования." << std::endl;
        return {};
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        std::cerr << "Ошибка инициализации шифрования AES." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len = 0, ciphertextLen = 0;

    if (!EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)plaintext.data(), plaintext.size())) {
        std::cerr << "Ошибка шифрования." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    ciphertextLen += len;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext.data() + ciphertextLen, &len)) {
        std::cerr << "Ошибка завершения шифрования." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    ciphertextLen += len;

    ciphertext.resize(ciphertextLen);
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

std::string aesDecrypt(const std::vector<unsigned char>& ciphertext, const std::string& keyFile) {
    std::ifstream file(keyFile, std::ios::binary);
    if (!file) {
        std::cerr << "Не удалось открыть файл с ключом." << std::endl;
        return {};
    }

    const int keyLength = 32;
    const int ivLength = 16;
    unsigned char key[keyLength];
    unsigned char iv[ivLength];

    file.read((char*)key, keyLength);
    file.read((char*)iv, ivLength);
    file.close();

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Ошибка создания контекста расшифрования." << std::endl;
        return {};
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        std::cerr << "Ошибка инициализации расшифрования AES." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    std::vector<unsigned char> plaintext(ciphertext.size());
    int len = 0, plaintextLen = 0;

    if (!EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size())) {
        std::cerr << "Ошибка расшифрования." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    plaintextLen += len;

    if (!EVP_DecryptFinal_ex(ctx, plaintext.data() + plaintextLen, &len)) {
        std::cerr << "Ошибка завершения расшифрования." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    plaintextLen += len;

    plaintext.resize(plaintextLen);
    EVP_CIPHER_CTX_free(ctx);

    return std::string(plaintext.begin(), plaintext.end());
}