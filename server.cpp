#include <iostream>                             // BIBLIOTECA PARA ENTRADA/SALIDA ESTÁNDAR
#include <unordered_map>                        // BIBLIOTECA PARA MAPAS HASH
#include <thread>                               // BIBLIOTECA PARA USO DE HILOS
#include <vector>                               // BIBLIOTECA PARA VECTORES DINÁMICOS
#include <mutex>                                // BIBLIOTECA PARA MUTEX Y SINCRONIZACIÓN
#include <sstream>                              // BIBLIOTECA PARA FLUJOS DE TEXTO
#include <iomanip>                              // BIBLIOTECA PARA FORMATEO DE TEXTO
#include <chrono>                               // BIBLIOTECA PARA FECHAS Y HORAS
#include <fstream>                              // BIBLIOTECA PARA MANEJO DE ARCHIVOS
#include <filesystem>                           // BIBLIOTECA PARA OPERACIONES CON EL SISTEMA DE ARCHIVOS
#include <random>                               // BIBLIOTECA PARA GENERAR VALORES ALEATORIOS
#include <winsock2.h>                           // BIBLIOTECA PARA SOCKETS EN WINDOWS
#include <ws2tcpip.h>                           // EXTENSIÓN PARA SOPORTE DE TCP/IP
#include "tinyxml2.h"                           // BIBLIOTECA PARA MANEJO DE ARCHIVOS XML
#include <openssl/evp.h>                        // BIBLIOTECA DE OPENSSL PARA CRIPTOGRAFÍA
#include "common_crypto.h"                      // CABECERA PERSONALIZADA PARA FUNCIONES CRIPTOGRÁFICAS
#include "logger.h"                             // CABECERA PERSONALIZADA PARA REGISTRO DE EVENTOS
Logger logger;                                  // INSTANCIA GLOBAL DEL LOGGER

#pragma comment(lib, "Ws2_32.lib")              // INDICA AL ENLAZADOR QUE USE LA LIBRERÍA DE SOCKETS

std::mutex io_mutex;                            // MUTEX GLOBAL PARA PROTEGER LA SALIDA ESTÁNDAR Y ESTRUCTURAS COMPARTIDAS
std::unordered_map<int, SOCKET> clients;        // MAPA DE CLIENTES CONECTADOS (ID -> SOCKET)
std::unordered_map<int, std::vector<unsigned char>> client_keys;   // MAPA DE CLAVES DE SESIÓN POR CLIENTE
std::unordered_map<int, std::vector<unsigned char>> client_nonces; // MAPA DE NONCES POR CLIENTE

// FUNCIÓN QUE MUESTRA EL BANNER INICIAL DEL SERVIDOR
void banner_servidor() {
    std::lock_guard<std::mutex> lock(io_mutex);
    std::cout << "\n▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄\n";
    std::cout << "█─▄▄▄▄█▄─▄▄─█▄─▄▄▀█▄─█─▄█▄─▄▄─█▄─▄▄▀█\n";
    std::cout << "█▄▄▄▄─██─▄█▀██─▄─▄██▄▀▄███─▄█▀██─▄─▄█\n";
    std::cout << "█▄▄▄▄▄█▄▄▄▄▄█▄▄█▄▄███▄███▄▄▄▄▄█▄▄█▄▄█\n";
    std::cout << "\nDeveloped by @marichu_kt\n";
    std::cout << "GitHub: https://github.com/marichu-kt\n";
    std::cout << "Type 'help' to see available commands.\n\n";
}

// FUNCIÓN QUE DEVUELVE LA MARCA DE TIEMPO ACTUAL EN FORMATO [YYYY-MM-DD HH:MM:SS.MS]
std::string current_timestamp() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto itt = system_clock::to_time_t(now);
    auto tm = *std::localtime(&itt);
    auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    std::ostringstream oss;
    oss << "[" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S")
        << "." << std::setw(3) << std::setfill('0') << ms.count() << "]";
    return oss.str();
}

// GENERA UN ID ÚNICO DE CLIENTE ENTRE 1000 Y 9999 QUE NO ESTÉ EN USO
int generate_unique_id() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(1000, 9999);
    int id;
    do {
        id = dis(gen);
    } while (clients.count(id));
    return id;
}

// FUNCIÓN QUE MANEJA LA CONEXIÓN CON UN CLIENTE EN UN HILO INDEPENDIENTE
void client_handler(SOCKET client_socket, int client_id) {
    EVP_PKEY* server_keypair = generate_x25519_keypair();                  // GENERA PAR DE CLAVES DEL SERVIDOR
    unsigned char server_pubkey[PUBKEY_LEN];
    get_public_key(server_pubkey, server_keypair);                         // OBTIENE CLAVE PÚBLICA DEL SERVIDOR
    send(client_socket, (char*)server_pubkey, PUBKEY_LEN, 0);             // ENVÍA LA CLAVE PÚBLICA AL CLIENTE

    unsigned char client_pubkey[PUBKEY_LEN];
    if (recv(client_socket, (char*)client_pubkey, PUBKEY_LEN, MSG_WAITALL) != PUBKEY_LEN) return; // RECIBE CLAVE PÚBLICA DEL CLIENTE

    std::vector<unsigned char> key(KEY_LEN);
    compute_shared_secret(key, server_keypair, client_pubkey);            // DERIVA CLAVE SECRETA COMPARTIDA

    std::vector<unsigned char> nonce;
    generate_nonce(nonce);                                                // GENERA NONCE ALEATORIO
    send(client_socket, (char*)nonce.data(), nonce.size(), 0);           // ENVÍA EL NONCE AL CLIENTE

    // ENVÍA EL ID DEL CLIENTE
    uint32_t net_id = htonl(client_id);
    send(client_socket, (char*)&net_id, sizeof(net_id), 0);

    {
        std::lock_guard<std::mutex> lock(io_mutex);
        clients[client_id] = client_socket;
        client_keys[client_id] = key;
        client_nonces[client_id] = nonce;
        logger.log("Servidor", client_id, "Cliente conectado");
        std::cout << "[+] Cliente conectado con ID: " << client_id << "\n";
        std::cout << "mario@server:~$ ";
        std::cout.flush();
    }

    while (true) {
        uint32_t total_len_net;
        int received = recv(client_socket, (char*)&total_len_net, sizeof(total_len_net), MSG_WAITALL);
        if (received != sizeof(total_len_net)) break;
        uint32_t total_len = ntohl(total_len_net);
        if (total_len < TAG_LEN + 1) continue;

        std::vector<unsigned char> buffer(total_len);
        int total_received = 0;
        while (total_received < total_len) {
            int chunk = recv(client_socket, (char*)buffer.data() + total_received, total_len - total_received, 0);
            if (chunk <= 0) return;
            total_received += chunk;
        }

        unsigned char msg_type = buffer[0];
        std::vector<unsigned char> ciphertext(buffer.begin() + 1, buffer.end() - TAG_LEN);
        std::vector<unsigned char> tag(buffer.end() - TAG_LEN, buffer.end());

        try {
            auto plaintext = decrypt(ciphertext, key, nonce, tag);       // DESCIFRA EL MENSAJE RECIBIDO

            if (msg_type == 0x01) {
                std::string msg(plaintext.begin() + 1, plaintext.end());
                std::lock_guard<std::mutex> lock(io_mutex);
                std::cout << "\n" << current_timestamp() << " [Cliente " << client_id << "] " << msg << "\n";
                std::cout << "mario@server:~$ ";
                std::cout.flush();
            }
            else if (msg_type == 0xAA) {
                size_t offset = 0;

                // LEER ID DEL REMITENTE (4 BYTES)
                uint32_t sender_id = 0;
                for (int i = 0; i < 4; ++i) sender_id = (sender_id << 8) | plaintext[offset++];

                // LEER LONGITUD DEL NOMBRE DEL ARCHIVO (4 BYTES)
                uint32_t name_len = 0;
                for (int i = 0; i < 4; ++i) name_len = (name_len << 8) | plaintext[offset++];

                // LEER NOMBRE DEL ARCHIVO
                std::string filename(plaintext.begin() + offset, plaintext.begin() + offset + name_len);
                offset += name_len;

                // LEER TAMAÑO DEL ARCHIVO (8 BYTES)
                uint64_t file_size = 0;
                for (int i = 0; i < 8; ++i) file_size = (file_size << 8) | plaintext[offset++];

                // LEER CONTENIDO DEL ARCHIVO
                std::vector<unsigned char> file_data(plaintext.begin() + offset, plaintext.end());

                // GUARDAR ARCHIVO EN DISCO
                std::filesystem::create_directories("../received_files");
                std::string filepath = "../received_files/" + filename;
                std::ofstream out(filepath, std::ios::binary);
                if (out) {
                    out.write((char*)file_data.data(), file_data.size());
                    std::lock_guard<std::mutex> lock(io_mutex);
                    std::cout << "[*] Archivo recibido de Cliente " << sender_id << ": " << filename << " (" << file_size << " bytes)\n";
                    logger.log("Cliente", sender_id, "Archivo recibido: " + filename + " (" + std::to_string(file_size) + " bytes)");
                    std::cout << "mario@server:~$ ";
                    std::cout.flush();
                }
            }
        } catch (...) {
            std::cerr << "[!] Error al descifrar mensaje del cliente " << client_id << "\n";
        }
    }

    // LIMPIEZA TRAS DESCONECTAR CLIENTE
    std::lock_guard<std::mutex> lock(io_mutex);
    clients.erase(client_id);
    client_keys.erase(client_id);
    client_nonces.erase(client_id);
    std::cout << "[-] Cliente desconectado: " << client_id << "\n";
    logger.log("Servidor", client_id, "Cliente desconectado");
    closesocket(client_socket);
    std::cout << "mario@server:~$ ";
    std::cout.flush();
}

void server_input_loop() {
    while (true) {
        std::cout << "mario@server:~$ ";                    // MUESTRA EL PROMPT DEL SERVIDOR
        std::cout.flush();
        std::string line;
        std::getline(std::cin, line);                       // LEE LA LÍNEA INTRODUCIDA POR EL USUARIO

        if (line == "list") {
            std::lock_guard<std::mutex> lock(io_mutex);     // BLOQUEA ACCESO A LA CONSOLA Y CLIENTES
            std::cout << "[*] Connected clients:\n";
            for (const auto& [id, _] : clients)             // MUESTRA LOS IDS DE LOS CLIENTES CONECTADOS
                std::cout << "  ID: " << id << "\n";
        }

        // ENVÍA MENSAJE DEL SERVIDOR A UN CLIENTE ESPECÍFICO
        else if (line.rfind("send ", 0) == 0) {
            std::istringstream iss(line);
            std::string cmd;
            int target_id;
            iss >> cmd >> target_id;
            std::string msg;
            std::getline(iss, msg);
            if (clients.count(target_id)) {
                auto& sock = clients[target_id];
                auto& key = client_keys[target_id];
                auto& nonce = client_nonces[target_id];
                std::vector<unsigned char> payload = {0x01};                    // CÓDIGO DE MENSAJE TEXTO
                payload.insert(payload.end(), msg.begin() + 1, msg.end());      // AGREGA MENSAJE (SIN ESPACIO INICIAL)
                std::vector<unsigned char> tag;
                auto encrypted = encrypt(payload, key, nonce, tag);             // CIFRA EL MENSAJE
                encrypted.insert(encrypted.end(), tag.begin(), tag.end());
                uint32_t total_len = encrypted.size();
                uint32_t total_len_net = htonl(total_len);
                send(sock, (char*)&total_len_net, sizeof(total_len_net), 0);    // ENVÍA LONGITUD
                send(sock, (char*)encrypted.data(), encrypted.size(), 0);       // ENVÍA MENSAJE CIFRADO

                std::lock_guard<std::mutex> lock(io_mutex);
                std::cout << "[>] Message sent to Client " << target_id << "\n";
                logger.log("Servidor", target_id, msg.substr(1));              // REGISTRA EL MENSAJE EN EL LOG
            } else {
                std::cerr << "[!] Client not found\n";
            }
        }

        // ENVÍA MENSAJE BROADCAST A TODOS LOS CLIENTES
        else if (line.rfind("broadcast ", 0) == 0) {
            std::string msg = line.substr(10);
            std::lock_guard<std::mutex> lock(io_mutex);
            for (const auto& [id, sock] : clients) {
                auto& key = client_keys[id];
                auto& nonce = client_nonces[id];
                std::vector<unsigned char> payload = {0x04};                    // CÓDIGO DE BROADCAST
                payload.insert(payload.end(), msg.begin(), msg.end());
                std::vector<unsigned char> tag;
                auto encrypted = encrypt(payload, key, nonce, tag);             // CIFRA EL MENSAJE
                encrypted.insert(encrypted.end(), tag.begin(), tag.end());
                uint32_t total_len = encrypted.size();
                uint32_t total_len_net = htonl(total_len);
                send(sock, (char*)&total_len_net, sizeof(total_len_net), 0);    // ENVÍA LONGITUD
                send(sock, (char*)encrypted.data(), encrypted.size(), 0);       // ENVÍA MENSAJE CIFRADO
            }
            std::cout << "[>] Broadcast message sent to all clients\n";
            logger.log("Servidor", -1, "Broadcast: " + msg);                    // REGISTRA EL BROADCAST EN EL LOG
        }

        // MUESTRA MENÚ DE AYUDA
        else if (line == "help") {
            std::lock_guard<std::mutex> lock(io_mutex);
            std::cout << "\n  [ Secure Server Command Reference ]  \n";
            std::cout << "  help                         Display this command reference.\n";
            std::cout << "  list                         Show all connected clients.\n";
            std::cout << "  send <id> <message>          Send an encrypted message to a specific client.\n";
            std::cout << "  broadcast <message>          Send an encrypted broadcast message to all clients.\n";
            std::cout << "  exit                         Shut down the server and notify all clients.\n\n";
        }

        // CIERRA EL SERVIDOR Y NOTIFICA A TODOS LOS CLIENTES
        else if (line == "exit") {
            std::lock_guard<std::mutex> lock(io_mutex);
            std::cout << "[*] Shutting down server...\n";

            for (const auto& [id, sock] : clients) {
                std::vector<unsigned char> payload = { 0xFF };                 // CÓDIGO ESPECIAL DE APAGADO
                std::vector<unsigned char> tag;
                auto encrypted = encrypt(payload, client_keys[id], client_nonces[id], tag);
                encrypted.insert(encrypted.end(), tag.begin(), tag.end());
                uint32_t total_len = encrypted.size();
                uint32_t total_len_net = htonl(total_len);
                send(sock, (char*)&total_len_net, sizeof(total_len_net), 0);
                send(sock, (char*)encrypted.data(), encrypted.size(), 0);
                closesocket(sock);                                             // CIERRA CONEXIÓN CON CLIENTE
            }

            clients.clear();
            client_keys.clear();
            client_nonces.clear();
            std::cout << "[*] All clients have been disconnected.\n";
            logger.log("Servidor", -1, "Server terminated via 'exit' command.");
            exit(0);                                                           // CIERRA EL SERVIDOR
        }
    }
}

// CARGA LA CONFIGURACIÓN IP Y PUERTO DESDE EL ARCHIVO server.xml
bool load_config(std::string& ip, int& port) {
    tinyxml2::XMLDocument doc;
    if (doc.LoadFile("../src/server.xml") != tinyxml2::XML_SUCCESS) return false;
    auto* root = doc.FirstChildElement("config");
    if (!root) return false;
    ip = root->FirstChildElement("ip")->GetText();
    port = std::stoi(root->FirstChildElement("port")->GetText());
    return true;
}

// FUNCIÓN PRINCIPAL DEL SERVIDOR
int main(int argc, char* argv[]) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);                             // INICIALIZA LA LIBRERÍA WINSOCK

    std::string ip; int port;
    std::string configPath = "../src/server.xml";
    if (!load_config(ip, port)) {
        std::cerr << "[!] Error cargando configuración de " << configPath << "\n";
        return 1;
    }

    SOCKET server_fd = socket(AF_INET, SOCK_STREAM, 0);              // CREA SOCKET DEL SERVIDOR
    sockaddr_in address{};
    address.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &address.sin_addr);               // CONVIERTE IP A BINARIO
    address.sin_port = htons(port);                                  // CONVIERTE PUERTO A FORMATO DE RED
    bind(server_fd, (SOCKADDR*)&address, sizeof(address));           // ENLAZA IP Y PUERTO AL SOCKET
    listen(server_fd, SOMAXCONN);                                    // ESCUCHA CONEXIONES ENTRANTES

    std::cout << "[.] Ejecutando desde: " << std::filesystem::current_path() << "\n";
    std::cout << "[*] Esperando conexiones en " << ip << ":" << port << "...\n";
    banner_servidor();                                               // MUESTRA BANNER

    std::thread(server_input_loop).detach();                         // HILO PARA COMANDOS DEL ADMINISTRADOR

    while (true) {
        sockaddr_in client_addr;
        int addrlen = sizeof(client_addr);
        SOCKET client_socket = accept(server_fd, (SOCKADDR*)&client_addr, &addrlen);  // ACEPTA CLIENTE
        int client_id = generate_unique_id();                                         // GENERA ID ÚNICO
        std::thread(client_handler, client_socket, client_id).detach();              // MANEJA CLIENTE EN HILO
    }

    closesocket(server_fd);                                           // CIERRA SOCKET DEL SERVIDOR
    WSACleanup();                                                     // LIMPIA WINSOCK
    return 0;
}
