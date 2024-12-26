#ifndef RSA_GENERATOR_H
#define RSA_GENERATOR_H

#include <string>
#include <vector>

// Генерация RSA ключей
void generateRSAKeys(const std::string& entropyData, const std::string& publicKeyFilename, const std::string& privateKeyFilename);

// RSA шифрование файла
std::vector<unsigned char> rsaEncryptFile(const std::vector<unsigned char>& message, const std::string& publicKeyFilename);

// RSA расшифрование файла
std::vector<unsigned char> rsaDecryptFile(const std::vector<unsigned char>& encryptedData, const std::string& privateKeyFilename);

#endif // RSA_GENERATOR_H