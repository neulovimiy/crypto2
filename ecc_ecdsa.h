#ifndef ECC_ECDSA_H
#define ECC_ECDSA_H

#include <string>
#include <vector>

// Генерация ключей ECDSA с использованием энтропии
void generateECDSAKeys(const std::string& entropyData, const std::string& privateKeyFile, const std::string& publicKeyFile);

// Подпись файла с использованием приватного ключа ECDSA
std::vector<unsigned char> signFile(const std::string& filename, const std::string& privateKeyFile);

// Проверка подписи файла с использованием публичного ключа ECDSA
bool verifyFileSignature(const std::string& filename, const std::vector<unsigned char>& signature, const std::string& publicKeyFile);

#endif // ECC_ECDSA_H