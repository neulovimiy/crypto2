#include <iostream>
#include <fstream>
#include <filesystem>
#include <windows.h>
#include <vector>
#include <ctime>
#include <string>
#include <chrono>
#include <thread>
#include <openssl/crypto.h>
#include "rsa_generator.h"
#include "aes_generator.h"
#include "ecc_ecdsa.h"
#include <openssl/evp.h>
#include <limits>
#include <iomanip>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <sstream>
#include <shobjidl.h>
#include "resource.h"
#include <openssl/sha.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <random> // Для генерации случайных чисел
#pragma comment(lib, "advapi32.lib")
#define IDC_EDIT_HASH 101
#define IDC_BUTTON_COPY 102
#define IDC_EDIT_PASSWORD 103
#define IDC_BUTTON_DECRYPTION_PRIV_KEY 10

std::string messageN;
int progressPercent = 0;
std::string entropyData;

// Глобальные переменные для работы с прогрессом и сообщениями
HWND globalProgressHwnd = NULL;
size_t globalTotalSize = 0;

static UINT WM_UPDATE_PROGRESS = 0;
static UINT WM_RSA_DONE = 0;

// Функция для преобразования строки UTF-8 в UTF-16
std::wstring utf8_to_utf16(const std::string& utf8) {
    if (utf8.empty()) return std::wstring();
    int utf16_length = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
    if (utf16_length == 0) {
        return std::wstring();
    }
    std::vector<wchar_t> utf16_buffer(utf16_length);
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, utf16_buffer.data(), utf16_length);
    return std::wstring(utf16_buffer.data());
}

void showMessageN(const std::string& message) {
    std::wstring wmessage = utf8_to_utf16(message);
    MessageBoxW(NULL, wmessage.c_str(), L"info", MB_OK | MB_ICONINFORMATION);
}

// Функция для генерации случайного содержимого
std::string generateRandomContent(size_t size) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    std::string randomContent(size, '\0');
    for (size_t i = 0; i < size; ++i) {
        randomContent[i] = static_cast<char>(dis(gen));
    }
    return randomContent;
}

// Функция для открытия файла (диалог)
std::string openFileDialog(HWND hwnd, const std::string& title) {

    IFileOpenDialog* pFileOpen = NULL;
    HRESULT hr = CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_ALL, IID_IFileOpenDialog, (void**)&pFileOpen);
    if (FAILED(hr)) {
        return "";
    }

    // Устанавливаем заголовок диалога
    if (!title.empty()) {
        std::wstring wTitle = utf8_to_utf16(title);
        pFileOpen->SetTitle(wTitle.c_str());
    }

    // Отображаем диалог
    hr = pFileOpen->Show(hwnd);
    if (FAILED(hr)) {
        pFileOpen->Release();
        return "";
    }

    IShellItem* pItem = NULL;
    hr = pFileOpen->GetResult(&pItem);
    if (FAILED(hr)) {
        pFileOpen->Release();
        return "";
    }

    PWSTR pszFilePath = NULL;
    hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);
    pItem->Release();
    pFileOpen->Release();

    if (FAILED(hr) || !pszFilePath) {
        return "";
    }

    std::wstring wFilePath(pszFilePath);
    CoTaskMemFree(pszFilePath);
    std::string filePath(wFilePath.begin(), wFilePath.end());
    return filePath;
}

std::string saveFileDialog(HWND hwnd, const std::string& title, const std::string& filter) {
    OPENFILENAMEW ofn;
    wchar_t szFile[260] = {0};
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile) / sizeof(wchar_t);
    std::wstring wFilter = utf8_to_utf16(filter);
    ofn.lpstrFilter = wFilter.c_str();
    std::wstring wTitle = utf8_to_utf16(title);
    ofn.lpstrTitle = wTitle.c_str();
    ofn.nFilterIndex = 1;
    ofn.lpstrFile[0] = '\0';
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;
    if (GetSaveFileNameW(&ofn)) {
        std::wstring wFilePath(szFile);
        std::string filePath(wFilePath.begin(), wFilePath.end());
        return filePath;
    }
    return "";
}

// Отрисовка окна прогресса с двойной буферизацией
LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    // Сначала обрабатываем пользовательские сообщения, полученные через RegisterWindowMessageA
    if (message == WM_UPDATE_PROGRESS) {
        size_t processed = (size_t)wParam;
        if (globalTotalSize > 0) {
            progressPercent = (int)((processed * 100) / globalTotalSize);
        } else {
            progressPercent = 100;
        }
        RedrawWindow(hwnd, NULL, NULL, RDW_ERASE | RDW_INVALIDATE | RDW_UPDATENOW);
        return 0;
    } else if (message == WM_RSA_DONE) {
        BOOL success = (BOOL)wParam;
        DestroyWindow(hwnd); // Закрываем окно прогресса
        if (success) {
            showMessageN("Операция RSA успешно завершена!");
        } else {
            showMessageN("Операция RSA не завершена!");
        }
        std::remove("temp_decrypted_key.pem");
        return 0;
    }

    // Далее стандартная обработка системных сообщений
    switch (message) {
        case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            RECT clientRect;
            GetClientRect(hwnd, &clientRect);

            HDC memDC = CreateCompatibleDC(hdc);
            HBITMAP memBitmap = CreateCompatibleBitmap(hdc, clientRect.right - clientRect.left,
                                                       clientRect.bottom - clientRect.top);
            HBITMAP oldBitmap = (HBITMAP)SelectObject(memDC, memBitmap);

            // Заливаем фон
            HBRUSH whiteBrush = (HBRUSH)GetStockObject(WHITE_BRUSH);
            FillRect(memDC, &clientRect, whiteBrush);

            // Рисуем рамку прогрессбара
            HBRUSH blackBrush = CreateSolidBrush(RGB(0, 0, 0));
            HBRUSH greenBrush = CreateSolidBrush(RGB(0, 255, 0));
            HBRUSH oldBrush = (HBRUSH)SelectObject(memDC, blackBrush);
            Rectangle(memDC, 0, 0, clientRect.right, clientRect.bottom);

            // Заполненная часть
            int filledWidth = (clientRect.right - 10) * progressPercent / 100;
            SelectObject(memDC, greenBrush);
            Rectangle(memDC, 5, 5, filledWidth + 5, clientRect.bottom - 5);

            SelectObject(memDC, oldBrush);

            BitBlt(hdc, 0, 0, clientRect.right, clientRect.bottom, memDC, 0, 0, SRCCOPY);

            DeleteObject(blackBrush);
            DeleteObject(greenBrush);
            SelectObject(memDC, oldBitmap);
            DeleteObject(memBitmap);
            DeleteDC(memDC);

            EndPaint(hwnd, &ps);
        }
        break;

        case WM_DESTROY:
            // Здесь окно прогресса не вызывает PostQuitMessage
            break;

        default:
            return DefWindowProc(hwnd, message, wParam, lParam);
    }
    return 0;
}

// Функции AES шифрования/дешифрования
std::vector<unsigned char> aesEncrypt(const std::string& plaintext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    std::vector<unsigned char> ciphertext(plaintext.size() + 16);
    int len = 0, ciphertextLen = 0;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.data()), (int)plaintext.size());
    ciphertextLen += len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + ciphertextLen, &len);
    ciphertextLen += len;
    ciphertext.resize(ciphertextLen);
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

std::string aesDecrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    std::vector<unsigned char> plaintext(ciphertext.size());
    int len = 0, plaintextLen = 0;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), (int)ciphertext.size());
    plaintextLen += len;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + plaintextLen, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ""; // Ошибка расшифрования
    }
    plaintextLen += len;
    plaintext.resize(plaintextLen);
    EVP_CIPHER_CTX_free(ctx);
    return std::string(plaintext.begin(), plaintext.end());
}

// HEX конвертация
std::vector<unsigned char> hexStringToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        unsigned char byte = (unsigned char)std::stoi(hex.substr(i, 2), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

// Диалог для ввода ключа/iv
INT_PTR CALLBACK DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    static std::string *keyIvString = nullptr;
    switch (uMsg) {
        case WM_INITDIALOG:
            keyIvString = (std::string*)lParam;
            return TRUE;
        case WM_COMMAND:
            if (LOWORD(wParam) == IDOK) {
                char keyIvBuffer[512];
                GetDlgItemText(hwndDlg, IDC_KEY_IV, keyIvBuffer, (int)sizeof(keyIvBuffer));
                *keyIvString = keyIvBuffer;
                EndDialog(hwndDlg, IDOK);
                return TRUE;
            }
            break;
        case WM_CLOSE:
            EndDialog(hwndDlg, IDCANCEL);
            return TRUE;
    }
    return FALSE;
}

// Функция для запроса ключа и IV у пользователя
std::pair<std::string, std::string> getKeyAndIV(HWND hwnd) {
    std::string keyIvString;
    if (DialogBoxParam(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_DIALOG1), hwnd, DialogProc, (LPARAM)&keyIvString) != IDOK) {
        MessageBox(hwnd, "Key and IV input cancelled.", "Error", MB_OK | MB_ICONERROR);
        return std::make_pair("", "");
    }
    if (keyIvString.empty()) {
        MessageBox(hwnd, "Key and IV cannot be empty.", "Error", MB_OK | MB_ICONERROR);
        return std::make_pair("", "");
    }
    size_t colonPos = keyIvString.find(':');
    if (colonPos == std::string::npos) {
        MessageBox(hwnd, "Invalid format. Please enter the key and IV separated by a colon.", "Error", MB_OK | MB_ICONERROR);
        return std::make_pair("", "");
    }
    std::string keyHex = keyIvString.substr(0, colonPos);
    std::string ivHex = keyIvString.substr(colonPos + 1);
    return std::make_pair(keyHex, ivHex);
}

// Обёртки для rsa, aes, ecc функций
void handleRSAKeyGeneration(HWND hwnd, const std::string& entropyData, const std::string& keyHex, const std::string& ivHex) {
    std::vector<unsigned char> key = hexStringToBytes(keyHex);
    std::vector<unsigned char> iv = hexStringToBytes(ivHex);

    // Определяем пути для ключей в корневой папке проекта
    std::string publicKeyPath = "rsa_public_key.pem";
    std::string privateKeyPath = "rsa_private_key.pem";

    // Генерация ключей RSA
    generateRSAKeys(entropyData, publicKeyPath, privateKeyPath);

    // Чтение закрытого ключа
    std::ifstream privateKeyIn(privateKeyPath, std::ios::binary);
    if (!privateKeyIn) {
        showMessageN("Ошибка: Не удается прочитать файл закрытого ключа.");
        return;
    }
    std::vector<unsigned char> rawPrivateKey((std::istreambuf_iterator<char>(privateKeyIn)), std::istreambuf_iterator<char>());
    privateKeyIn.close();

    std::string rawPrivateKeyStr(rawPrivateKey.begin(), rawPrivateKey.end());
    std::vector<unsigned char> encryptedKey = aesEncrypt(rawPrivateKeyStr, key, iv);

    // Запись зашифрованного закрытого ключа
    std::ofstream privateKeyOut(privateKeyPath, std::ios::binary);
    if (!privateKeyOut) {
        showMessageN("Ошибка при сохранении зашифрованного закрытого ключа.");
        return;
    }
    privateKeyOut.write(reinterpret_cast<const char*>(encryptedKey.data()), (std::streamsize)encryptedKey.size());
    privateKeyOut.close();
}

void handleAESKeyGeneration(HWND hwnd, const std::string& entropyData) {
    // Определяем пути для ключа и IV в корневой папке проекта
    std::string keyFile = "aes_key.key";
    std::string ivFile = "aes_iv.iv";

    // Генерация ключей
    generateAESKeys(entropyData, keyFile, ivFile);
}

void handleECDSAKeyGeneration(HWND hwnd, const std::string& entropyData, const std::string& keyHex, const std::string& ivHex) {
    std::vector<unsigned char> key = hexStringToBytes(keyHex);
    std::vector<unsigned char> iv = hexStringToBytes(ivHex);

    // Определяем пути для ключей в корневой папке проекта
    std::string privateKeyPath = "ecdsa_private_key.pem";
    std::string publicKeyPath = "ecdsa_public_key.pem";

    // Генерация ключей ECDSA
    generateECDSAKeys(entropyData, privateKeyPath, publicKeyPath);

    // Чтение закрытого ключа
    std::ifstream privateKeyIn(privateKeyPath);
    if (!privateKeyIn) {
        showMessageN("Ошибка: Не удается прочитать файл закрытого ключа.");
        return;
    }
    std::string rawPrivateKey((std::istreambuf_iterator<char>(privateKeyIn)), std::istreambuf_iterator<char>());
    privateKeyIn.close();

    // Шифрование закрытого ключа
    std::vector<unsigned char> encryptedKey = aesEncrypt(rawPrivateKey, key, iv);

    // Сохранение зашифрованного закрытого ключа
    std::ofstream privateKeyOut(privateKeyPath, std::ios::binary);
    if (!privateKeyOut) {
        showMessageN("Ошибка при сохранении зашифрованного закрытого ключа.");
        return;
    }
    privateKeyOut.write((char*)encryptedKey.data(), (std::streamsize)encryptedKey.size());
    privateKeyOut.close();

    showMessageN("Ключи были успешно сгенерированы, а закрытые ключи зашифрованы.");
}

void handleAESEncryption(HWND hwnd) {
    // Указываем пути к файлам ключа и IV
    std::string keyFile = "aes_key.key"; // Путь к файлу ключа
    std::string ivFile = "aes_iv.iv";    // Путь к файлу IV

    // Проверяем, существуют ли файлы ключа и IV
    std::ifstream keyIn(keyFile, std::ios::binary);
    std::ifstream ivIn(ivFile, std::ios::binary);
    if (!keyIn || !ivIn) {
        showMessageN("Ошибка: Не удалось открыть файлы ключа или IV.");
        return;
    }

    // Читаем ключ и IV
    std::vector<unsigned char> key(32), iv(16);
    keyIn.read((char*)key.data(), (std::streamsize)key.size());
    ivIn.read((char*)iv.data(), (std::streamsize)iv.size());

    // Закрываем файлы ключа и IV
    keyIn.close();
    ivIn.close();

    // Запрашиваем у пользователя файл для шифрования
    std::string inputFile = openFileDialog(hwnd, "Выберите файл для шифрования");
    if (inputFile.empty()) return;

    // Запрашиваем у пользователя файл для сохранения зашифрованных данных
    std::string outputFile = openFileDialog(hwnd, "Выберите файл для сохранения зашифрованных данных");
    if (outputFile.empty()) return;

    // Открываем входной файл для чтения
    std::ifstream fileIn(inputFile, std::ios::binary);
    if (!fileIn) {
        showMessageN("Ошибка при открытии входного файла.");
        return;
    }

    // Получаем размер входного файла
    fileIn.seekg(0, std::ios::end);
    size_t totalSize = (size_t)fileIn.tellg();
    fileIn.seekg(0, std::ios::beg);

    // Открываем выходной файл для записи
    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile) {
        showMessageN("Ошибка при открытии выходного файла для записи.");
        return;
    }

    // Создаем окно прогресса
    HWND progressWindow = CreateWindowExW(
            0,
            L"ProgressWindowClass",
            L"АES Шифрование...",
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
            CW_USEDEFAULT, CW_USEDEFAULT,
            400, 100,
            hwnd, NULL,
            GetModuleHandle(NULL), NULL
    );
    progressPercent = 0;
    globalProgressHwnd = progressWindow;
    globalTotalSize = totalSize; // totalSize получаем так же, как и сейчас
    ShowWindow(progressWindow, SW_SHOW);
    UpdateWindow(progressWindow);

    // Инициализируем контекст AES
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data());

    const size_t CHUNK_SIZE = 16777216;
    std::vector<unsigned char> inBuffer(CHUNK_SIZE), outBuffer(CHUNK_SIZE + 16);
    int outLen = 0;
    size_t processed = 0;

    // Обрабатываем файл по частям
    while (!fileIn.eof()) {
        fileIn.read((char*)inBuffer.data(), (std::streamsize)CHUNK_SIZE);
        std::streamsize bytesRead = fileIn.gcount();
        if (bytesRead <= 0) break;
        if (!EVP_EncryptUpdate(ctx, outBuffer.data(), &outLen, inBuffer.data(), (int)bytesRead)) {
            showMessageN("Ошибка AES шифрования");
            EVP_CIPHER_CTX_free(ctx);
            return;
        }
        outFile.write((char*)outBuffer.data(), outLen);
        processed += (size_t)bytesRead;
        progressPercent = (int)((processed * 100) / totalSize);
        RedrawWindow(progressWindow, NULL, NULL, RDW_ERASE | RDW_INVALIDATE | RDW_UPDATENOW);
    }

    // Завершаем шифрование
    if (!EVP_EncryptFinal_ex(ctx, outBuffer.data(), &outLen)) {
        showMessageN("Ошибка завершения AES шифрования");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    outFile.write((char*)outBuffer.data(), outLen);
    EVP_CIPHER_CTX_free(ctx);

    // Закрываем окно прогресса
    if (globalProgressHwnd) {
        DestroyWindow(globalProgressHwnd);
        globalProgressHwnd = NULL;
    }

    showMessageN("Файл был успешно зашифрован и сохранен!");
}

void handleAESDecryption(HWND hwnd) {
    // Указываем пути к файлам ключа и IV
    std::string keyFile = "aes_key.key"; // Путь к файлу ключа
    std::string ivFile = "aes_iv.iv";    // Путь к файлу IV

    // Проверяем, существуют ли файлы ключа и IV
    std::ifstream keyIn(keyFile, std::ios::binary);
    std::ifstream ivIn(ivFile, std::ios::binary);
    if (!keyIn || !ivIn) {
        showMessageN("Ошибка: Не удалось открыть файлы ключа или IV.");
        return;
    }

    // Читаем ключ и IV
    std::vector<unsigned char> key(32), iv(16);
    keyIn.read((char*)key.data(), (std::streamsize)key.size());
    ivIn.read((char*)iv.data(), (std::streamsize)iv.size());

    // Закрываем файлы ключа и IV
    keyIn.close();
    ivIn.close();

    // Запрашиваем у пользователя файл для расшифровки
    std::string inputFile = openFileDialog(hwnd, "Выберите зашифрованный файл для расшифровки");
    if (inputFile.empty()) {
        showMessageN("Выбор входного файла был отменен.");
        return;
    }

    // Запрашиваем у пользователя файл для сохранения расшифрованных данных
    std::string outputFile = openFileDialog(hwnd, "Выберите файл для сохранения расшифрованных данных");
    if (outputFile.empty()) {
        showMessageN("Выбор выходного файла был отменен.");
        return;
    }

    // Открываем входной файл для чтения
    std::ifstream fileIn(inputFile, std::ios::binary);
    if (!fileIn) {
        showMessageN("Ошибка при открытии входного файла.");
        return;
    }

    // Получаем размер входного файла
    fileIn.seekg(0, std::ios::end);
    size_t totalSize = (size_t)fileIn.tellg();
    fileIn.seekg(0, std::ios::beg);

    // Открываем выходной файл для записи
    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile) {
        showMessageN("Ошибка при открытии выходного файла для записи.");
        return;
    }

    // Инициализируем контекст AES для расшифрования
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data())) {
        showMessageN("Ошибка инициализации AES расшифрования.");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    // Создаем окно прогресса
    HWND progressWindow = CreateWindowExW(
            0,
            L"ProgressWindowClass",
            L"АES Расшифровка...",
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
            CW_USEDEFAULT, CW_USEDEFAULT,
            400, 100,
            hwnd, NULL,
            GetModuleHandle(NULL), NULL
    );
    progressPercent = 0;
    globalProgressHwnd = progressWindow;
    globalTotalSize = totalSize; // totalSize получаем так же, как и сейчас
    ShowWindow(progressWindow, SW_SHOW);
    UpdateWindow(progressWindow);

    const size_t CHUNK_SIZE = 16777216;
    std::vector<unsigned char> inBuffer(CHUNK_SIZE), outBuffer(CHUNK_SIZE + 16);
    int outLen = 0;
    size_t processed = 0;

    // Обрабатываем файл по частям
    while (!fileIn.eof()) {
        fileIn.read((char*)inBuffer.data(), (std::streamsize)CHUNK_SIZE);
        std::streamsize bytesRead = fileIn.gcount();
        if (bytesRead <= 0) break;

        if (!EVP_DecryptUpdate(ctx, outBuffer.data(), &outLen, inBuffer.data(), (int)bytesRead)) {
            showMessageN("Ошибка расшифрования AES (Update).");
            EVP_CIPHER_CTX_free(ctx);
            return;
        }

        if (outLen > 0) {
            outFile.write((char*)outBuffer.data(), outLen);
        }

        processed += (size_t)bytesRead;
        progressPercent = (int)((processed * 100) / totalSize);
        RedrawWindow(progressWindow, NULL, NULL, RDW_ERASE | RDW_INVALIDATE | RDW_UPDATENOW);
    }

    // Завершаем расшифрование
    if (!EVP_DecryptFinal_ex(ctx, outBuffer.data(), &outLen)) {
        showMessageN("Ошибка при завершении AES расшифрования. Возможно неверный ключ или повреждён файл.");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if (outLen > 0) {
        outFile.write((char*)outBuffer.data(), outLen);
    }

    EVP_CIPHER_CTX_free(ctx);

    // Закрываем окно прогресса
    if (globalProgressHwnd) {
        DestroyWindow(globalProgressHwnd);
        globalProgressHwnd = NULL;
    }

    showMessageN("Файл был успешно расшифрован и сохранен в: " + outputFile);
}
EC_KEY* loadECDSAPublicKey(const std::string& publicKeyPath) {
    FILE* fp = fopen(publicKeyPath.c_str(), "rb");
    if (!fp) return nullptr;
    EC_KEY* ecKey = PEM_read_EC_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    return ecKey;
}

EC_KEY* loadECDSAPrivateKey(const std::string& privateKeyPath) {
    FILE* fp = fopen(privateKeyPath.c_str(), "rb");
    if (!fp) return nullptr;
    EC_KEY* ecKey = PEM_read_ECPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return ecKey;
}

// Инкрементное чтение и подпись
std::vector<unsigned char> signFileIncremental(const std::string& inputFile, const std::string& privateKeyPath, HWND hwndParent) {
    EC_KEY* ecKey = loadECDSAPrivateKey(privateKeyPath);
    if (!ecKey) {
        showMessageN("Ошибка при загрузке приватного ключа ECDSA.");
        return {};
    }

    // Открываем входной файл
    std::ifstream fileIn(inputFile, std::ios::binary);
    if (!fileIn) {
        showMessageN("Ошибка при открытии входного файла для подписи.");
        EC_KEY_free(ecKey);
        return {};
    }

    // Узнаём размер файла для прогрессбара
    fileIn.seekg(0, std::ios::end);
    size_t totalSize = (size_t)fileIn.tellg();
    fileIn.seekg(0, std::ios::beg);

    // Создаём окно прогресса
    HWND progressWindow = CreateWindowExW(
        0,
        L"ProgressWindowClass",
        L"ECDSA Подписание...",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT,
        400, 100,
        hwndParent, NULL,
        GetModuleHandle(NULL), NULL
    );
    progressPercent = 0;
    globalTotalSize = totalSize;
    globalProgressHwnd = progressWindow;
    ShowWindow(progressWindow, SW_SHOW);
    UpdateWindow(progressWindow);

    // Инициализация SHA-256 контекста
    SHA256_CTX shaCtx;
    SHA256_Init(&shaCtx);

    const size_t CHUNK_SIZE = 16777216;
    std::vector<unsigned char> buffer(CHUNK_SIZE);
    size_t processed = 0;

    while (!fileIn.eof()) {
        fileIn.read((char*)buffer.data(), (std::streamsize)CHUNK_SIZE);
        std::streamsize bytesRead = fileIn.gcount();
        if (bytesRead <= 0) break;

        // Обновляем хэш
        SHA256_Update(&shaCtx, buffer.data(), (size_t)bytesRead);

        processed += (size_t)bytesRead;
        progressPercent = (int)((processed * 100) / totalSize);
        RedrawWindow(progressWindow, NULL, NULL, RDW_ERASE | RDW_INVALIDATE | RDW_UPDATENOW);
    }

    // Закрываем окно прогресса
    if (globalProgressHwnd) {
        DestroyWindow(globalProgressHwnd);
        globalProgressHwnd = NULL;
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &shaCtx);

    // Подписываем хэш
    ECDSA_SIG* signature = ECDSA_do_sign(hash, SHA256_DIGEST_LENGTH, ecKey);
    if (!signature) {
        showMessageN("Ошибка при создании ECDSA подписи.");
        EC_KEY_free(ecKey);
        return {};
    }

    const BIGNUM *r, *s;
    ECDSA_SIG_get0(signature, &r, &s);

    // Конвертация R и S в вектор
    int rLen = BN_num_bytes(r);
    int sLen = BN_num_bytes(s);
    std::vector<unsigned char> signatureBytes(rLen + sLen);
    BN_bn2bin(r, &signatureBytes[0]);
    BN_bn2bin(s, &signatureBytes[rLen]);

    ECDSA_SIG_free(signature);
    EC_KEY_free(ecKey);

    return signatureBytes;
}

// Инкрементная проверка подписи
bool verifyFileSignatureIncremental(const std::string& inputFile, const std::vector<unsigned char>& signature, const std::string& publicKeyPath, HWND hwndParent) {
    EC_KEY* ecKey = loadECDSAPublicKey(publicKeyPath);
    if (!ecKey) {
        showMessageN("Ошибка при загрузке публичного ключа ECDSA.");
        return false;
    }

    // Парсим подпись на r и s
    // Предполагаем, что первая половина - r, вторая - s (как мы записывали выше)
    size_t half = signature.size() / 2;
    BIGNUM* r = BN_bin2bn(signature.data(), (int)half, NULL);
    BIGNUM* s = BN_bin2bn(signature.data() + half, (int)(signature.size() - half), NULL);
    ECDSA_SIG* sig = ECDSA_SIG_new();
    ECDSA_SIG_set0(sig, r, s);

    // Открываем входной файл
    std::ifstream fileIn(inputFile, std::ios::binary);
    if (!fileIn) {
        showMessageN("Ошибка при открытии входного файла для проверки подписи.");
        ECDSA_SIG_free(sig);
        EC_KEY_free(ecKey);
        return false;
    }

    fileIn.seekg(0, std::ios::end);
    size_t totalSize = (size_t)fileIn.tellg();
    fileIn.seekg(0, std::ios::beg);

    HWND progressWindow = CreateWindowExW(
        0,
        L"ProgressWindowClass",
        L"ECDSA Проверка подписи...",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT,
        400, 100,
        hwndParent, NULL,
        GetModuleHandle(NULL), NULL
    );
    progressPercent = 0;
    globalTotalSize = totalSize;
    globalProgressHwnd = progressWindow;
    ShowWindow(progressWindow, SW_SHOW);
    UpdateWindow(progressWindow);

    SHA256_CTX shaCtx;
    SHA256_Init(&shaCtx);

    const size_t CHUNK_SIZE = 16777216;
    std::vector<unsigned char> buffer(CHUNK_SIZE);
    size_t processed = 0;

    while (!fileIn.eof()) {
        fileIn.read((char*)buffer.data(), (std::streamsize)CHUNK_SIZE);
        std::streamsize bytesRead = fileIn.gcount();
        if (bytesRead <= 0) break;

        SHA256_Update(&shaCtx, buffer.data(), (size_t)bytesRead);

        processed += (size_t)bytesRead;
        progressPercent = (int)((processed * 100) / totalSize);
        RedrawWindow(progressWindow, NULL, NULL, RDW_ERASE | RDW_INVALIDATE | RDW_UPDATENOW);
    }

    if (globalProgressHwnd) {
        DestroyWindow(globalProgressHwnd);
        globalProgressHwnd = NULL;
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &shaCtx);

    int verifyStatus = ECDSA_do_verify(hash, SHA256_DIGEST_LENGTH, sig, ecKey);

    ECDSA_SIG_free(sig);
    EC_KEY_free(ecKey);

    return (verifyStatus == 1);
}

void handleMessageSigning(HWND hwnd) {
    std::string encryptedPrivateKeyPath = openFileDialog(hwnd, "Выберите зашифрованный закрытый ключ ECDSA");
    if (encryptedPrivateKeyPath.empty()) {
        showMessageN("Выбор зашифрованного закрытого ключа ECDSA отменен.");
        return;
    }

    std::string keyIvString;
    if (DialogBoxParam(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_DIALOG1), hwnd, DialogProc, (LPARAM)&keyIvString) != IDOK) {
        MessageBox(hwnd, "Key and IV input cancelled.", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    size_t colonPos = keyIvString.find(':');
    if (colonPos == std::string::npos) {
        MessageBox(hwnd, "Invalid format. Please enter the key and IV separated by a colon.", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    std::string keyHex = keyIvString.substr(0, colonPos);
    std::string ivHex = keyIvString.substr(colonPos + 1);
    std::vector<unsigned char> key = hexStringToBytes(keyHex);
    std::vector<unsigned char> iv = hexStringToBytes(ivHex);

    std::ifstream encryptedPrivateKeyIn(encryptedPrivateKeyPath, std::ios::binary);
    if (!encryptedPrivateKeyIn) {
        showMessageN("Ошибка: Не удается прочитать зашифрованный файл с закрытым ключом.");
        return;
    }

    std::vector<unsigned char> encryptedKey((std::istreambuf_iterator<char>(encryptedPrivateKeyIn)), std::istreambuf_iterator<char>());
    encryptedPrivateKeyIn.close();
    std::string decryptedKey = aesDecrypt(encryptedKey, key, iv);
    if (decryptedKey.empty()) {
        showMessageN("Ошибка: Не удалось расшифровать файл с ключом.");
        return;
    }

    std::string tempDecryptedKeyPath = "temp_decrypted_key.pem";
    {
        std::ofstream decryptedPrivateKeyOut(tempDecryptedKeyPath, std::ios::trunc | std::ios::binary);
        if (!decryptedPrivateKeyOut) {
            showMessageN("Ошибка при сохранении расшифрованного закрытого ключа.");
            return;
        }
        decryptedPrivateKeyOut.write(decryptedKey.data(), (std::streamsize)decryptedKey.size());
    }

    std::string inputFile = openFileDialog(hwnd, "Выберите файл для подписи");
    if (inputFile.empty()) {
        std::remove(tempDecryptedKeyPath.c_str());
        return;
    }

    std::string outputFile = openFileDialog(hwnd, "Выберите файл для сохранения подписи");
    if (outputFile.empty()) {
        std::remove(tempDecryptedKeyPath.c_str());
        return;
    }

    // Используем инкрементную функцию для подписи:
    std::vector<unsigned char> signature = signFileIncremental(inputFile, tempDecryptedKeyPath, hwnd);
    if (signature.empty()) {
        showMessageN("Ошибка при создании подписи.");
        std::remove(tempDecryptedKeyPath.c_str());
        return;
    }

    // Сохраняем подпись в hex виде:
    std::string hexSignature;
    for (unsigned char c : signature) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02X", c);
        hexSignature += hex;
    }

    std::ofstream outFile(outputFile);
    if (!outFile) {
        showMessageN("Ошибка при открытии файла для записи подписи.");
        std::remove(tempDecryptedKeyPath.c_str());
        return;
    }
    outFile << hexSignature;
    outFile.close();

    std::remove(tempDecryptedKeyPath.c_str());
    showMessageN("Подпись успешно создана и сохранена в: " + outputFile);
}

void handleSignatureVerification(HWND hwnd) {
    // Указываем путь к открытому ключу ECDSA
    std::string publicKeyFile = "ecdsa_public_key.pem";

    // Проверяем, существует ли файл с открытым ключом
    std::ifstream publicKeyIn(publicKeyFile, std::ios::binary);
    if (!publicKeyIn) {
        showMessageN("Ошибка: Не удается открыть файл с открытым ключом ECDSA.");
        return;
    }

    // Запрашиваем у пользователя файл для проверки
    std::string inputFile = openFileDialog(hwnd, "Выберите файл для проверки");
    if (inputFile.empty()) {
        showMessageN("Выбор входного файла был отменен.");
        return;
    }

    // Запрашиваем у пользователя файл подписи
    std::string signatureFile = openFileDialog(hwnd, "Выберите файл подписи");
    if (signatureFile.empty()) {
        showMessageN("Выбор файла подписи был отменен.");
        return;
    }

    // Читаем подпись из файла
    std::ifstream sigFileIn(signatureFile);
    if (!sigFileIn) {
        showMessageN("Ошибка при открытии файла подписи.");
        return;
    }
    std::string hexSignature((std::istreambuf_iterator<char>(sigFileIn)), std::istreambuf_iterator<char>());
    sigFileIn.close();

    // Преобразуем подпись из hex в бинарный формат
    std::vector<unsigned char> signature;
    for (size_t i = 0; i < hexSignature.length(); i += 2) {
        std::string byteString = hexSignature.substr(i, 2);
        unsigned char byte = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
        signature.push_back(byte);
    }

    // Проверяем подпись
    bool valid = verifyFileSignatureIncremental(inputFile, signature, publicKeyFile, hwnd);
    if (valid) {
        showMessageN("Подпись действительна.");
    } else {
        showMessageN("Подпись не действительна.");
    }
}

// Структура для параметров шифрования/расшифрования RSA в потоке
struct RSAParams {
    HWND parentHwnd;
    HWND progressWindow;
    std::string keyFile;
    std::string inputFile;
    std::string outputFile;
    bool encrypt; // true для шифрования, false для расшифрования
};

// Поток для RSA шифрования/расшифрования
DWORD WINAPI RSAThread(LPVOID lpParam) {
    RSAParams* params = (RSAParams*)lpParam;
    FILE *fp = fopen(params->keyFile.c_str(), "rb");
    if (!fp) {
        PostMessage(params->parentHwnd, WM_RSA_DONE, FALSE, 0);
        delete params;
        return 1;
    }

    RSA *rsa = NULL;
    if (params->encrypt) {
        rsa = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
    } else {
        rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    }
    fclose(fp);
    if (!rsa) {
        PostMessage(params->parentHwnd, WM_RSA_DONE, FALSE, 0);
        delete params;
        return 1;
    }

    std::ifstream fileIn(params->inputFile, std::ios::binary);
    std::ofstream outFile(params->outputFile, std::ios::binary);
    if (!fileIn || !outFile) {
        RSA_free(rsa);
        PostMessage(params->parentHwnd, WM_RSA_DONE, FALSE, 0);
        delete params;
        return 1;
    }

    fileIn.seekg(0, std::ios::end);
    size_t totalSize = (size_t)fileIn.tellg();
    fileIn.seekg(0, std::ios::beg);

    globalTotalSize = totalSize;
    globalProgressHwnd = params->progressWindow;

    int rsaBlockSize = RSA_size(rsa);
    int inBlockSize = params->encrypt ? (rsaBlockSize - 11) : rsaBlockSize;
    std::vector<unsigned char> inBuffer(inBlockSize);
    std::vector<unsigned char> outBuffer(rsaBlockSize);

    size_t processed = 0;
    while (!fileIn.eof()) {
        fileIn.read((char*)inBuffer.data(), (std::streamsize)inBlockSize);
        std::streamsize bytesRead = fileIn.gcount();
        if (bytesRead <= 0) break;

        int resultLen;
        if (params->encrypt) {
            resultLen = RSA_public_encrypt((int)bytesRead, inBuffer.data(), outBuffer.data(), rsa, RSA_PKCS1_PADDING);
        } else {
            resultLen = RSA_private_decrypt((int)bytesRead, inBuffer.data(), outBuffer.data(), rsa, RSA_PKCS1_PADDING);
        }

        if (resultLen == -1) {
            RSA_free(rsa);
            PostMessage(params->progressWindow, WM_RSA_DONE, FALSE, 0);
            delete params;
            return 1;
        }

        outFile.write((char*)outBuffer.data(), resultLen);
        processed += (size_t)bytesRead;

        // Обновляем прогресс
        PostMessage(params->progressWindow, WM_UPDATE_PROGRESS, (WPARAM)processed, 0);
    }

    std::cout << "RSA Clean!\n";
    RSA_free(rsa);
    std::cout << "RSA Cleaned!\n";
    PostMessage(params->progressWindow, WM_RSA_DONE, TRUE, 0);
    delete params;
    return 0;
}



void handleRSACryptoEncryption(HWND hwnd) {
    // Путь к файлу с открытым ключом по умолчанию
    std::string defaultPublicKeyFile = "rsa_public_key.pem";

    // Проверяем, существует ли файл с открытым ключом
    if (!std::filesystem::exists(defaultPublicKeyFile)) {
        // Если файл не существует, запрашиваем у пользователя выбор файла
        defaultPublicKeyFile = openFileDialog(hwnd, "Выберите открытый ключ RSA");
        if (defaultPublicKeyFile.empty()) return; // Пользователь отменил выбор
    }

    std::string inputFile = openFileDialog(hwnd, "Выберите файл для шифрования");
    if (inputFile.empty()) return;

    std::string outputFile = saveFileDialog(hwnd, "Выберите файл для сохранения зашифрованных данных", "All Files (*.*)\0*.*\0");
    if (outputFile.empty()) return;

    std::ifstream fileIn(inputFile, std::ios::binary);
    if (!fileIn) {
        showMessageN("Ошибка при открытии входного файла.");
        return;
    }

    fileIn.seekg(0, std::ios::end);
    size_t totalSize = (size_t)fileIn.tellg();
    fileIn.seekg(0, std::ios::beg);

    // Создаём окно прогресса
    HWND progressWindow = CreateWindowExW(
            0,
            L"ProgressWindowClass",
            L"Encryption RSA...",
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
            CW_USEDEFAULT, CW_USEDEFAULT,
            400, 100,
            hwnd, NULL,
            GetModuleHandle(NULL), NULL
    );
    progressPercent = 0;
    globalTotalSize = totalSize;
    globalProgressHwnd = progressWindow;
    ShowWindow(progressWindow, SW_SHOW);
    UpdateWindow(progressWindow);

    RSAParams* params = new RSAParams;
    params->parentHwnd = hwnd;
    params->progressWindow = progressWindow;
    params->keyFile = defaultPublicKeyFile; // Используем путь к ключу
    params->inputFile = inputFile;
    params->outputFile = outputFile;
    params->encrypt = true;

    CreateThread(NULL, 0, RSAThread, params, 0, NULL);
}
void overwriteFileWithRandomData(const std::string& filePath) {
    const size_t bufferSize = 1024; // Размер буфера для случайных данных
    std::vector<unsigned char> randomData(bufferSize);

    // Генерация случайных данных
    HCRYPTPROV hCryptProv;
    if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0)) {
        CryptGenRandom(hCryptProv, bufferSize, randomData.data());
        CryptReleaseContext(hCryptProv, 0);
    } else {
        // Если CryptGenRandom недоступен, используем rand()
        for (size_t i = 0; i < bufferSize; ++i) {
            randomData[i] = static_cast<unsigned char>(rand() % 256);
        }
    }

    // Перезапись файла
    std::ofstream outFile(filePath, std::ios::binary | std::ios::trunc);
    if (outFile) {
        outFile.write(reinterpret_cast<char*>(randomData.data()), bufferSize);
        outFile.close();
    } else {
        showMessageN("Ошибка: Не удалось перезаписать файл случайными данными.");
    }
}
void handleCompleteDecryption(HWND hwnd) {
    // Шаг 1: Выбор файла с зашифрованным ключом
    std::string encryptedPrivateKeyPath = openFileDialog(hwnd, "Выберите зашифрованный закрытый ключ RSA");
    if (encryptedPrivateKeyPath.empty()) {
        showMessageN("Выбор зашифрованного файла с закрытым ключом RSA был отменен.");
        return;
    }

    // Шаг 2: Ввод ключа и вектора инициализации
    std::string keyIvString;
    if (DialogBoxParam(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_DIALOG1), hwnd, DialogProc, (LPARAM)&keyIvString) != IDOK) {
        MessageBox(hwnd, "Key and IV input cancelled.", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Проверка формата ввода (ключ:вектор)
    size_t colonPos = keyIvString.find(':');
    if (colonPos == std::string::npos) {
        MessageBox(hwnd, "Invalid format. Please enter the key and IV separated by a colon.", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    std::string keyHex = keyIvString.substr(0, colonPos);
    std::string ivHex = keyIvString.substr(colonPos + 1);
    std::vector<unsigned char> key = hexStringToBytes(keyHex);
    std::vector<unsigned char> iv = hexStringToBytes(ivHex);

    // Шаг 3: Чтение зашифрованного ключа
    std::ifstream encryptedPrivateKeyIn(encryptedPrivateKeyPath, std::ios::binary);
    if (!encryptedPrivateKeyIn) {
        showMessageN("Ошибка: Не удается прочитать зашифрованный файл с закрытым ключом.");
        return;
    }
    std::vector<unsigned char> encryptedKey((std::istreambuf_iterator<char>(encryptedPrivateKeyIn)), std::istreambuf_iterator<char>());
    encryptedPrivateKeyIn.close();

    // Шаг 4: Расшифровка ключа
    std::string decryptedKey = aesDecrypt(encryptedKey, key, iv);
    if (decryptedKey.empty()) {
        showMessageN("Ошибка: Не удалось расшифровать файл.");
        std::remove("temp_decrypted_key.pem"); // Удаление временного файла в случае ошибки
        return;
    }

    // Шаг 5: Сохранение расшифрованного ключа во временный файл
    std::string tempDecryptedKeyPath = "temp_decrypted_key.pem";
    {
        std::ofstream decryptedPrivateKeyOut(tempDecryptedKeyPath, std::ios::binary);
        if (!decryptedPrivateKeyOut) {
            showMessageN("Ошибка при сохранении расшифрованного закрытого ключа.");
            std::remove(tempDecryptedKeyPath.c_str()); // Удаление временного файла в случае ошибки
            return;
        }
        decryptedPrivateKeyOut.write(decryptedKey.data(), (std::streamsize)decryptedKey.size());
    }

    // Шаг 6: Выбор файла для расшифровки
    std::string inputFile = openFileDialog(hwnd, "Выберите файл для расшифровки");
    if (inputFile.empty()) {
        std::remove(tempDecryptedKeyPath.c_str());
        return;
    }

    // Шаг 7: Выбор файла для сохранения расшифрованных данных
    std::string outputFile = openFileDialog(hwnd, "Выберите файл для сохранения расшифрованных данных");
    if (outputFile.empty()) {
        std::remove(tempDecryptedKeyPath.c_str());
        return;
    }

    // Шаг 8: Создание окна прогресса
    HWND progressWindow = CreateWindowExW(
            0,
            L"ProgressWindowClass",
            L"Decryption RSA...",
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
            CW_USEDEFAULT, CW_USEDEFAULT,
            400, 100,
            hwnd, NULL,
            GetModuleHandle(NULL), NULL
    );
    ShowWindow(progressWindow, SW_SHOW);
    UpdateWindow(progressWindow);

    // Шаг 9: Запуск потока для расшифровки
    RSAParams* params = new RSAParams;
    params->parentHwnd = hwnd;
    params->progressWindow = progressWindow;
    params->keyFile = tempDecryptedKeyPath;
    params->inputFile = inputFile;
    params->outputFile = outputFile;
    params->encrypt = false;

    CreateThread(NULL, 0, RSAThread, params, 0, NULL);

    // Шаг 10: Удаление временного файла после завершения
    std::atexit([]() {
        std::remove("temp_decrypted_key.pem");
    });
}

// Функция для генерации ключа и IV
std::string toHexString(const std::vector<unsigned char>& data) {
    std::ostringstream hexStream;
    for (unsigned char byte : data) {
        hexStream << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    return hexStream.str();
}

std::pair<std::string, std::string> generateKeyAndIV() {
    std::vector<unsigned char> key(32);
    if (RAND_bytes(key.data(), (int)key.size()) != 1) {
        std::cerr << "Ошибка генерации AES-ключа." << std::endl;
        return std::make_pair("", "");
    }

    std::vector<unsigned char> iv(16);
    if (RAND_bytes(iv.data(), (int)iv.size()) != 1) {
        std::cerr << "Ошибка генерации IV." << std::endl;
        return std::make_pair("", "");
    }

    std::string keyHex = toHexString(key);
    std::string ivHex = toHexString(iv);
    return std::make_pair(keyHex, ivHex);
}

// Парольное окно
LRESULT CALLBACK PasswordWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | ES_READONLY,
                           10, 50, 755, 30, hwnd, (HMENU)IDC_EDIT_PASSWORD, GetModuleHandle(NULL), NULL);
            break;
        }
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}
LRESULT CALLBACK HashWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            // Создаем элемент управления Edit для отображения хеша
            HWND hEdit = CreateWindowEx(
                    WS_EX_CLIENTEDGE, "Edit", "",
                    WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL,
                    10, 10, 780, 100, hwnd, (HMENU)IDC_EDIT_HASH, GetModuleHandle(NULL), NULL);
            SendMessage(hEdit, EM_SETREADONLY, TRUE, 0); // Делаем поле только для чтения

            // Создаем кнопку "Скопировать"
            HWND hButton = CreateWindowEx(
                    0, "Button", "Copy",
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    350, 120, 100, 30, hwnd, (HMENU)IDC_BUTTON_COPY, GetModuleHandle(NULL), NULL);
            break;
        }
        case WM_COMMAND: {
            if (LOWORD(wParam) == IDC_BUTTON_COPY) {
                // Копируем текст из поля Edit в буфер обмена
                HWND hEdit = GetDlgItem(hwnd, IDC_EDIT_HASH);
                int textLength = GetWindowTextLength(hEdit);
                if (textLength > 0) {
                    std::wstring text(textLength + 1, L'\0');
                    GetWindowTextW(hEdit, &text[0], textLength + 1);
                    OpenClipboard(hwnd);
                    EmptyClipboard();
                    HGLOBAL hGlob = GlobalAlloc(GMEM_FIXED, (textLength + 1) * sizeof(wchar_t));
                    memcpy(GlobalLock(hGlob), text.c_str(), (textLength + 1) * sizeof(wchar_t));
                    GlobalUnlock(hGlob);
                    SetClipboardData(CF_UNICODETEXT, hGlob);
                    CloseClipboard();
                }
            }
            break;
        }
        case WM_CLOSE:
            DestroyWindow(hwnd);
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam); // Corrected here
    }
    return 0;
}

void showHashWindow(HWND parentHwnd, const std::string& hash) {
    // Регистрируем класс окна
    WNDCLASS wc = {};
    wc.lpfnWndProc = HashWindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "HashWindowClass";
    RegisterClass(&wc);

    // Создаем окно
    HWND hwnd = CreateWindowEx(
            0, "HashWindowClass", "Hash file",
            WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 815, 200,
            parentHwnd, NULL, GetModuleHandle(NULL), NULL);

    // Устанавливаем текст в поле Edit
    HWND hEdit = GetDlgItem(hwnd, IDC_EDIT_HASH);
    std::wstring hashWStr = std::wstring(hash.begin(), hash.end());
    SetWindowTextW(hEdit, hashWStr.c_str());

    // Показываем окно
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    // Цикл обработки сообщений
    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}
std::string calculateFileHash(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        showMessageN("Ошибка: не удалось открыть файл для вычисления хеша.");
        return "";
    }

    // Инициализация контекста SHA-256
    SHA256_CTX sha256;
    if (!SHA256_Init(&sha256)) {
        showMessageN("Ошибка: не удалось инициализировать контекст SHA-256.");
        return "";
    }

    // Чтение файла блоками и обновление хеша
    const size_t bufferSize = 4096; // Размер буфера для чтения
    std::vector<unsigned char> buffer(bufferSize);
    while (file.good()) {
        file.read(reinterpret_cast<char*>(buffer.data()), bufferSize);
        std::streamsize bytesRead = file.gcount();
        if (bytesRead > 0) {
            if (!SHA256_Update(&sha256, buffer.data(), static_cast<size_t>(bytesRead))) {
                showMessageN("Ошибка: не удалось обновить хеш.");
                return "";
            }
        }
    }

    // Завершение вычисления хеша
    unsigned char hash[SHA256_DIGEST_LENGTH];
    if (!SHA256_Final(hash, &sha256)) {
        showMessageN("Ошибка: не удалось завершить вычисление хеша.");
        return "";
    }

    // Преобразование хеша в строку в формате HEX
    std::ostringstream hexStream;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        hexStream << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return hexStream.str();
}

void handleFileHashCalculation(HWND hwnd) {
    // Открываем диалог выбора файла
    std::string filePath = openFileDialog(hwnd, "Выберите файл для вычисления хеша");
    if (filePath.empty()) {
        showMessageN("Выбор файла отменен.");
        return;
    }

    // Вычисляем хеш файла
    std::string hash = calculateFileHash(filePath);
    if (hash.empty()) {
        showMessageN("Ошибка при вычислении хеша файла.");
        return;
    }

    // Отображаем хеш в новом окне
    showHashWindow(hwnd, hash);
}
void showPassword(const std::string& password) {
    WNDCLASS wc = {};
    wc.lpfnWndProc = PasswordWindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "PasswordWindowClass";
    RegisterClass(&wc);
    HWND hwnd = CreateWindowEx(0, "PasswordWindowClass", "It's secret", WS_OVERLAPPEDWINDOW,
                               CW_USEDEFAULT, CW_USEDEFAULT, 815, 200, NULL, NULL, GetModuleHandle(NULL), NULL);
    HWND hEdit = GetDlgItem(hwnd, IDC_EDIT_PASSWORD);
    SetWindowText(hEdit, password.c_str());
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

// Окно и кнопки
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    if ((uMsg == WM_UPDATE_PROGRESS && WM_UPDATE_PROGRESS != 0) || 
        (WM_UPDATE_PROGRESS != 0 && RegisterWindowMessageA("WM_UPDATE_PROGRESS") == uMsg)) {
        // Обновление прогресса
        size_t processed = (size_t)wParam;
        if (globalTotalSize > 0) {
            progressPercent = (int)((processed * 100) / globalTotalSize);
        } else {
            progressPercent = 100;
        }
        if (globalProgressHwnd != NULL) {
            RedrawWindow(globalProgressHwnd, NULL, NULL, RDW_ERASE | RDW_INVALIDATE | RDW_UPDATENOW);
        }
        return 0;
    }

    if ((uMsg == WM_RSA_DONE && WM_RSA_DONE != 0) ||
        (WM_RSA_DONE != 0 && RegisterWindowMessageA("WM_RSA_DONE") == uMsg)) {
        BOOL success = (BOOL)wParam;

        // Получаем указатель на params из lParam
        RSAParams* params = reinterpret_cast<RSAParams*>(lParam);

        if (globalProgressHwnd) {
            DestroyWindow(globalProgressHwnd);
            globalProgressHwnd = NULL;
        }

        if (success) {
            showMessageN("Операция RSA успешно завершена!");
        } else {
            showMessageN("Операция RSA не завершена!");

            // Перезапись выходного файла случайными данными
            overwriteFileWithRandomData(params->outputFile);
        }

        // Удаление временного ключа
        std::remove("temp_decrypted_key.pem");

        // Освобождаем память, выделенную для params
        delete params;
        return 0;
    }
    switch (uMsg) {
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case 1: // Генерация RSA ключей
                {
                    auto [keyHex, ivHex] = getKeyAndIV(hwnd);
                    if (keyHex.empty() || ivHex.empty()) {
                        return 0;
                    }
                    handleRSAKeyGeneration(hwnd, entropyData, keyHex, ivHex);
                    handleAESKeyGeneration(hwnd, entropyData);
                    handleECDSAKeyGeneration(hwnd, entropyData, keyHex, ivHex);
                }
                    break;
                case 4: // RSA шифрование
                    handleRSACryptoEncryption(hwnd);
                    break;
                case 5: // RSA расшифрование
                    handleCompleteDecryption(hwnd);
                    break;
                case 6: // AES шифрование
                    handleAESEncryption(hwnd);
                    break;
                case 7: // AES расшифрование
                    handleAESDecryption(hwnd);
                    break;
                case 8: // ECDSA подписать
                    handleMessageSigning(hwnd);
                    break;
                case 9: // ECDSA проверить подпись
                    handleSignatureVerification(hwnd);
                    break;
                case 10:
                    handleFileHashCalculation(hwnd);
                    break;
                case 0: // Выход
                    PostQuitMessage(0);
                    break;
                default:
                    break;
            }
            break;
        case WM_CLOSE:
            PostQuitMessage(0);
            return 0;
        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

HWND createMainWindow(HINSTANCE hInstance) {
    const char CLASS_NAME[] = "MainWindow";
    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    if (!RegisterClass(&wc)) {
        std::cerr << "Ошибка регистрации класса окна!" << std::endl;
        return nullptr;
    }
    HWND hwnd = CreateWindowEx(
            0, CLASS_NAME, "Menu", WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT, CW_USEDEFAULT, 315, 600, nullptr, nullptr, hInstance, nullptr
    );
    if (hwnd == nullptr) {
        std::cerr << "Ошибка создания окна!" << std::endl;
        return nullptr;
    }
    return hwnd;
}

void createButtons(HWND hwnd, HINSTANCE hInstance) {
    int buttonWidth = 200;
    int buttonHeight = 30;
    int x = 50;
    int y = 50;
    int spacing = 10;
    std::wstring btnText1 = utf8_to_utf16("Генерация ключей");
    std::wstring btnText4 = utf8_to_utf16("RSA Шифрование");
    std::wstring btnText5 = utf8_to_utf16("RSA Расшифрование");
    std::wstring btnText6 = utf8_to_utf16("AES Шифрование");
    std::wstring btnText7 = utf8_to_utf16("AES Расшифрование");
    std::wstring btnText8 = utf8_to_utf16("ECDSA подписать");
    std::wstring btnText9 = utf8_to_utf16("ECDSA проверить подпись");
    std::wstring btnText10 = utf8_to_utf16("Извлечь хеш");
    std::wstring btnText12 = utf8_to_utf16("Выход");

    CreateWindowW(L"BUTTON", btnText1.c_str(), WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                  x, y, buttonWidth, buttonHeight, hwnd, (HMENU)1, hInstance, nullptr);

    y += buttonHeight + spacing;
    CreateWindowW(L"BUTTON", btnText4.c_str(), WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                  x, y, buttonWidth, buttonHeight, hwnd, (HMENU)4, hInstance, nullptr);

    y += buttonHeight + spacing;
    CreateWindowW(L"BUTTON", btnText5.c_str(), WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                  x, y, buttonWidth, buttonHeight, hwnd, (HMENU)5, hInstance, nullptr);

    y += buttonHeight + spacing;
    CreateWindowW(L"BUTTON", btnText6.c_str(), WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                  x, y, buttonWidth, buttonHeight, hwnd, (HMENU)6, hInstance, nullptr);

    y += buttonHeight + spacing;
    CreateWindowW(L"BUTTON", btnText7.c_str(), WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                  x, y, buttonWidth, buttonHeight, hwnd, (HMENU)7, hInstance, nullptr);

    y += buttonHeight + spacing;
    CreateWindowW(L"BUTTON", btnText8.c_str(), WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                  x, y, buttonWidth, buttonHeight, hwnd, (HMENU)8, hInstance, nullptr);

    y += buttonHeight + spacing;
    CreateWindowW(L"BUTTON", btnText9.c_str(), WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                  x, y, buttonWidth, buttonHeight, hwnd, (HMENU)9, hInstance, nullptr);

    y += buttonHeight + spacing;
    CreateWindowW(L"BUTTON", btnText10.c_str(), WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                  x, y, buttonWidth, buttonHeight, hwnd, (HMENU)10, hInstance, nullptr);

    y += buttonHeight + spacing;
    CreateWindowW(L"BUTTON", btnText12.c_str(), WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                  x, y, buttonWidth, buttonHeight, hwnd, (HMENU)0, hInstance, nullptr);
}

HWND CreateProgressWindow(HINSTANCE hInstance) {
    WNDCLASSEX wc = { 0 };
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszMenuName = NULL;
    wc.lpszClassName = "ProgressWindowClass";
    wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);
    RegisterClassEx(&wc);
    HWND hwndA = CreateWindowEx(WS_EX_OVERLAPPEDWINDOW,
                                "ProgressWindowClass",
                                "Process...",
                                WS_OVERLAPPEDWINDOW,
                                CW_USEDEFAULT, CW_USEDEFAULT,
                                400, 200,
                                NULL, NULL,
                                hInstance, NULL);
    if (hwndA == NULL) {
        MessageBoxA(NULL, "Ошибка создания окна", "Ошибка", MB_OK | MB_ICONERROR);
        return NULL;
    }
    ShowWindow(hwndA, SW_SHOW);
    UpdateWindow(hwndA);
    return hwndA;
}

std::string collectMouseEntropy(int maxDurationMs = 60000, int intervalMs = 10, int minMovements = 100) {
    std::string entropyData;
    POINT cursorPosition;
    POINT previousPosition = { -1, -1 };
    int movementCount = 0;
    auto start = GetTickCount();
    showMessageN("Двигайте мишкой для сбора энтропии...");
    HWND progressWindow = CreateProgressWindow(GetModuleHandle(NULL));
    while (true) {
        if (GetCursorPos(&cursorPosition)) {
            int deltaX = abs(cursorPosition.x - previousPosition.x);
            int deltaY = abs(cursorPosition.y - previousPosition.y);
            if (deltaX > 1 || deltaY > 1) {
                entropyData += std::to_string(cursorPosition.x);
                entropyData += std::to_string(cursorPosition.y);
                auto timestamp = std::chrono::high_resolution_clock::now().time_since_epoch().count();
                entropyData += std::to_string(timestamp);
                previousPosition = cursorPosition;
                movementCount++;
                progressPercent = (movementCount * 100) / minMovements;
                RedrawWindow(progressWindow, NULL, NULL, RDW_ERASE | RDW_INVALIDATE | RDW_UPDATENOW);
            }
        }
        if ((GetTickCount() - start) >= (DWORD)maxDurationMs && movementCount < minMovements) {
            std::cerr << "\nНе удалось собрать достаточно энтропии." << std::endl;
            DestroyWindow(progressWindow);
            return {};
        }
        if (movementCount >= minMovements) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
    }
    DestroyWindow(progressWindow);

    std::ofstream entropyFile("entropy.txt");
    if (entropyFile.is_open()) {
        entropyFile << entropyData;
        entropyFile.close();
    } else {
        std::cerr << "Не удалось открыть файл для записи энтропии." << std::endl;
    }
    return entropyData;
}
// Функция для очистки OpenSSL
void cleanupOpenSSL() {
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
}

int main() {
    // Инициализация COM и консоли
    CoInitialize(NULL);
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    // Инициализация OpenSSL
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);

    // Регистрация пользовательских сообщений
    WM_UPDATE_PROGRESS = RegisterWindowMessageA("WM_UPDATE_PROGRESS");
    WM_RSA_DONE = RegisterWindowMessageA("WM_RSA_DONE");

    // Список файлов, которые нужно проверить
    std::vector<std::string> requiredFiles = {
            "entropy.txt",
            "aes_iv.iv",
            "aes_key.key",
            "ecdsa_private_key.pem",
            "ecdsa_public_key.pem",
            "rsa_private_key.pem",
            "rsa_public_key.pem"
    };

    bool allFilesExist = true;
    for (const auto& file : requiredFiles) {
        if (!std::filesystem::exists(file)) {
            allFilesExist = false;
            std::cerr << "Файл " << file << " не найден." << std::endl;
        }
    }

    if (allFilesExist) {
        // Все файлы существуют, продолжаем выполнение
        HINSTANCE hInstance = GetModuleHandle(nullptr);
        HWND hwnd = createMainWindow(hInstance);
        if (hwnd == nullptr) {
            std::cerr << "Не удалось создать главное окно." << std::endl;
            cleanupOpenSSL();
            CoUninitialize();
            return 1;
        }

        ShowWindow(hwnd, SW_SHOW);
        UpdateWindow(hwnd);
        createButtons(hwnd, hInstance);

        MSG msg = {};
        while (GetMessage(&msg, nullptr, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    } else {
        // Если не все файлы существуют, начинаем сбор энтропии и генерируем ключи
        int maxDurationMs = 60000;
        int intervalMs = 10;
        int minMovements = 100;

        std::thread entropyThread([&]() {
            entropyData = collectMouseEntropy(maxDurationMs, intervalMs, minMovements);
        });

        // Ждем завершения сбора энтропии
        while (true) {
            if (progressPercent >= 100) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
        }

        entropyThread.join(); // Дожидаемся завершения потока

        auto keyAndIVHex = generateKeyAndIV();
        if (keyAndIVHex.first.empty() || keyAndIVHex.second.empty()) {
            std::cerr << "Ошибка генерации ключа или IV." << std::endl;
            cleanupOpenSSL();
            CoUninitialize();
            return 1;
        }

        std::string password = keyAndIVHex.first + ":" + keyAndIVHex.second;
        showMessageN("Сфоткай, запиши на листок или как-то по другому запомни следующее окно.");
        showPassword(password);

        HINSTANCE hInstance = GetModuleHandle(nullptr);
        HWND hwnd = createMainWindow(hInstance);
        if (hwnd == nullptr) {
            std::cerr << "Не удалось создать главное окно." << std::endl;
            cleanupOpenSSL();
            CoUninitialize();
            return 1;
        }

        ShowWindow(hwnd, SW_SHOW);
        UpdateWindow(hwnd);
        createButtons(hwnd, hInstance);

        MSG msg = {};
        while (GetMessage(&msg, nullptr, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    // Очистка OpenSSL и завершение работы COM
    cleanupOpenSSL();
    CoUninitialize();

    return 0;
}
