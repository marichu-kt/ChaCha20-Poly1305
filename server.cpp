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

SOCKET client_socket;              // SOCKET CLIENTE
std::vector<unsigned char> key, nonce; // CLAVE Y NONCE

std::string current_timestamp();   // DECLARACIÓN TIMESTAMP

void banner_servidor() {
    std::cout << "▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄\n";
    std::cout << "█─▄▄▄▄█▄─▄▄─█▄─▄▄▀█▄─█─▄█▄─▄▄─█▄─▄▄▀█\n";
    std::cout << "█▄▄▄▄─██─▄█▀██─▄─▄██▄▀▄███─▄█▀██─▄─▄█\n";
    std::cout << "█▄▄▄▄▄█▄▄▄▄▄█▄▄█▄▄███▄███▄▄▄▄▄█▄▄█▄▄█\n\n";
}

bool read_loop() {                // LEE MENSAJES DEL CLIENTE
    while (true) {
        unsigned char buffer[1024];                             // BUFFER DE ENTRADA
        int bytes = recv(client_socket, (char*)buffer, sizeof(buffer), 0); // LEE SOCKET
        if (bytes <= 0) return false;                           // DESCONECTADO
        if (bytes <= TAG_LEN) continue;                         // MENSAJE INVÁLIDO

        std::vector<unsigned char> ciphertext(buffer, buffer + bytes - TAG_LEN); // SEPARA CIFRADO
        std::vector<unsigned char> tag(buffer + bytes - TAG_LEN, buffer + bytes); // SEPARA TAG

        try {
            auto plaintext = decrypt(ciphertext, key, nonce, tag); // DESCIFRA MENSAJE
            std::string msg(plaintext.begin(), plaintext.end());   // CONVIERTE A TEXTO
            std::cout << "\r\33[2K" << current_timestamp() << " [Cliente] " << msg << "\n"; // IMPRIME
            std::cout << "mario@server:~$ ";                    // PROMPT
            std::cout.flush();                                  // LIMPIA BUFFER
        } catch (const std::exception& e) {
            std::cerr << "\n[!] Error al descifrar: " << e.what() << "\n"; // ERROR AUTENTICACIÓN
        }
    }
}

bool write_loop() {              // ENVÍA MENSAJES AL CLIENTE
    while (true) {
        std::cout << "mario@server:~$ ";     // PROMPT
        std::cout.flush();                  // LIMPIA BUFFER
        std::string msg;
        std::getline(std::cin, msg);        // LEE MENSAJE
        if (msg.empty()) continue;          // IGNORA VACÍO

        std::vector<unsigned char> tag;                                  // CREA TAG
        auto encrypted = encrypt(std::vector<unsigned char>(msg.begin(), msg.end()), key, nonce, tag); // CIFRA
        encrypted.insert(encrypted.end(), tag.begin(), tag.end());       // AÑADE TAG
        int sent = send(client_socket, (char*)encrypted.data(), encrypted.size(), 0); // ENVÍA
        if (sent == SOCKET_ERROR) return false; // ERROR AL ENVIAR
    }
}

std::string current_timestamp() { // TIMESTAMP FORMATEADO
    using namespace std::chrono;
    auto now = system_clock::now();                                 // AHORA
    auto itt = system_clock::to_time_t(now);                        // FORMATO TIME_T
    auto tm = *std::localtime(&itt);                                // LOCALTIME
    auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000; // MILISEGUNDOS

    std::ostringstream oss;
    oss << "[" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S")           // FECHA Y HORA
        << "." << std::setw(3) << std::setfill('0') << ms.count() << "]"; // MILISEGUNDOS
    return oss.str();                                               // RETORNA STRING
}

int main() {                    // FUNCIÓN PRINCIPAL
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2,2), &wsaData);         // INICIA WINSOCK

    SOCKET server_fd = socket(AF_INET, SOCK_STREAM, 0); // CREA SOCKET
    if (server_fd == INVALID_SOCKET) {                 // ERROR CREANDO
        std::cerr << "[!] Error creando socket.\n";
        return 1;
    }

    sockaddr_in address{};                   // ESTRUCTURA DE DIRECCIÓN
    address.sin_family = AF_INET;            // IPV4
    address.sin_addr.s_addr = INADDR_ANY;    // ESCUCHA TODAS LAS IP
    address.sin_port = htons(PORT);          // PUERTO ESCUCHA

    if (bind(server_fd, (SOCKADDR*)&address, sizeof(address)) == SOCKET_ERROR) { // VINCULA
        std::cerr << "[!] Error en bind.\n";
        closesocket(server_fd); WSACleanup(); return 1;
    }

    listen(server_fd, 1);                    // ESCUCHA CONEXIONES
    std::cout << "[*] Esperando conexión en el puerto " << PORT << "...\n"; // MENSAJE INICIAL

    while (true) {
        int addrlen = sizeof(address);       // TAMAÑO DIRECCIÓN
        client_socket = accept(server_fd, (SOCKADDR*)&address, &addrlen); // ACEPTA CLIENTE
        if (client_socket == INVALID_SOCKET) {
            std::cerr << "[!] Error en accept.\n";
            continue;
        }

        banner_servidor();                   // BANNER BIENVENIDA
        generate_key(key);                   // GENERA CLAVE
        generate_nonce(nonce);               // GENERA NONCE

        send(client_socket, (char*)key.data(), key.size(), 0);     // ENVÍA CLAVE
        send(client_socket, (char*)nonce.data(), nonce.size(), 0); // ENVÍA NONCE

        std::thread r([]() { if (!read_loop()) closesocket(client_socket); }); // HILO LECTURA
        std::thread w([]() { if (!write_loop()) closesocket(client_socket); }); // HILO ESCRITURA
        r.join(); w.join();                 // ESPERA A HILOS

        std::cout << "[*] Esperando nueva conexión...\n"; // MENSAJE REINTENTO
    }

    closesocket(server_fd);     // CIERRA SERVIDOR
    WSACleanup();               // LIMPIA WINSOCK
    return 0;
}
