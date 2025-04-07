#include <iostream>
#include <vector>
#include <thread>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "common_crypto.h"

#pragma comment(lib, "Ws2_32.lib")

#define PORT 40000

SOCKET sock;                      // SOCKET DEL CLIENTE
std::vector<unsigned char> key(KEY_LEN), nonce(NONCE_LEN); // CLAVE Y NONCE

std::string current_timestamp();  // PROTOTIPO TIMESTAMP

void banner_cliente() {
    std::cout << "▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄\n";
    std::cout << "█─▄▄▄─█▄─▄███▄─▄█▄─▄▄─█▄─▀█▄─▄█─▄─▄─█\n";
    std::cout << "█─███▀██─██▀██─███─▄█▀██─█▄▀─████─███\n";
    std::cout << "█▄▄▄▄▄█▄▄▄▄▄█▄▄▄█▄▄▄▄▄█▄▄▄██▄▄██▄▄▄██\n\n";
}

bool read_loop() {               // LEE MENSAJES DEL SERVIDOR
    while (true) {
        unsigned char buffer[1024];                             // BUFFER DE ENTRADA
        int len = recv(sock, (char*)buffer, sizeof(buffer), 0); // RECIBE DATOS
        if (len <= 0) return false;                              // DESCONECTADO
        if (len <= TAG_LEN) continue;                            // MENSAJE INVÁLIDO

        std::vector<unsigned char> ciphertext(buffer, buffer + len - TAG_LEN); // SEPARA CIFRADO
        std::vector<unsigned char> tag(buffer + len - TAG_LEN, buffer + len);  // SEPARA TAG

        try {
            auto decrypted = decrypt(ciphertext, key, nonce, tag); // DESCIFRA
            std::string msg(decrypted.begin(), decrypted.end());   // CONVIERTE A STRING
            std::cout << "\r\33[2K" << current_timestamp() << " [Servidor] " << msg << "\n"; // MUESTRA
            std::cout << "mario@client:~$ ";                       // PROMPT
            std::cout.flush();                                     // LIMPIA BUFFER
        } catch (const std::exception& e) {
            std::cerr << "\n[!] Error de descifrado: " << e.what() << "\n"; // ERROR
        }
    }
}

bool write_loop() {              // ENVÍA MENSAJES AL SERVIDOR
    while (true) {
        std::cout << "mario@client:~$ ";   // PROMPT
        std::cout.flush();                // LIMPIA BUFFER
        std::string msg;
        std::getline(std::cin, msg);     // LEE MENSAJE
        if (msg.empty()) continue;       // SALTA SI VACÍO

        std::vector<unsigned char> tag;                                // TAG DE AUTENTICACIÓN
        auto encrypted = encrypt(std::vector<unsigned char>(msg.begin(), msg.end()), key, nonce, tag); // CIFRA
        encrypted.insert(encrypted.end(), tag.begin(), tag.end());     // AÑADE TAG AL FINAL
        int sent = send(sock, (char*)encrypted.data(), encrypted.size(), 0); // ENVÍA
        if (sent == SOCKET_ERROR) return false; // ERROR AL ENVIAR
    }
}

std::string current_timestamp() { // OBTIENE TIMESTAMP FORMATEADO
    using namespace std::chrono;
    auto now = system_clock::now();                                 // TIEMPO ACTUAL
    auto itt = system_clock::to_time_t(now);                        // CONVIERTE A TIME_T
    auto tm = *std::localtime(&itt);                                // LOCALTIME
    auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000; // MILISEGUNDOS

    std::ostringstream oss;
    oss << "[" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S")           // FECHA Y HORA
        << "." << std::setw(3) << std::setfill('0') << ms.count() << "]"; // MILISEGUNDOS
    return oss.str();                                               // DEVUELVE STRING
}

int main() {                    // FUNCIÓN PRINCIPAL
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) { // INICIA WINSOCK
        std::cerr << "[!] Error al iniciar Winsock.\n";
        return 1;
    }

    sockaddr_in serv_addr{};                    // ESTRUCTURA DIRECCIÓN
    serv_addr.sin_family = AF_INET;             // IPV4
    serv_addr.sin_port = htons(PORT);           // PUERTO
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // IP LOCAL

    while (true) {
        sock = socket(AF_INET, SOCK_STREAM, 0);             // CREA SOCKET
        if (sock == INVALID_SOCKET) {                       // ERROR
            std::cerr << "[!] Error creando socket.\n";
            WSACleanup(); return 1;
        }
        if (connect(sock, (SOCKADDR*)&serv_addr, sizeof(serv_addr)) == 0) { // INTENTA CONECTAR
            banner_cliente();                         // MUESTRA BANNER
            recv(sock, (char*)key.data(), KEY_LEN, 0);    // RECIBE CLAVE
            recv(sock, (char*)nonce.data(), NONCE_LEN, 0); // RECIBE NONCE

            std::thread r([]() { if (!read_loop()) closesocket(sock); }); // HILO LECTURA
            std::thread w([]() { if (!write_loop()) closesocket(sock); }); // HILO ESCRITURA
            r.join(); w.join(); // ESPERA A HILOS
        } else {
            std::cout << "[.] Esperando servidor...\n"; // ESPERA
            closesocket(sock);                          // CIERRA SOCKET
            std::this_thread::sleep_for(std::chrono::seconds(1)); // ESPERA 1 SEG
        }
    }

    WSACleanup(); // FINALIZA WINSOCK
    return 0;
}
