#ifndef AES_GENERATOR_H
#define AES_GENERATOR_H

#include <string>
#include <vector>

// Генерация AES ключа и IV с использованием энтропии
void generateAESKeys(const std::string& entropyData, const std::string& keyFile, const std::string& ivFile);

// AES шифрование
std::vector<unsigned char> aesEncrypt(const std::string& plaintext, const std::string& keyFile);

// AES расшифрование
std::string aesDecrypt(const std::vector<unsigned char>& ciphertext, const std::string& keyFile);

#endif // AES_GENERATOR_H