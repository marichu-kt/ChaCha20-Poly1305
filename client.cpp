#include <iostream>                         // BIBLIOTECA PARA ENTRADA/SALIDA ESTÁNDAR
#include <vector>                           // BIBLIOTECA PARA USO DE VECTORES DINÁMICOS
#include <thread>                           // BIBLIOTECA PARA MANEJO DE HILOS
#include <sstream>                          // BIBLIOTECA PARA FLUJOS DE TEXTO EN MEMORIA
#include <iomanip>                          // BIBLIOTECA PARA MANIPULACIÓN DE FORMATO DE SALIDA
#include <chrono>                           // BIBLIOTECA PARA MEDICIÓN DE TIEMPO
#include <ctime>                            // BIBLIOTECA PARA MANEJO DE FECHAS Y HORAS
#include <fstream>                          // BIBLIOTECA PARA MANEJO DE ARCHIVOS
#include <filesystem>                       // BIBLIOTECA PARA OPERACIONES DE SISTEMA DE ARCHIVOS
#include <winsock2.h>                       // BIBLIOTECA PARA FUNCIONES DE SOCKET EN WINDOWS
#include <ws2tcpip.h>                       // BIBLIOTECA PARA SOPORTE ADICIONAL DE TCP/IP
#include "tinyxml2.h"                       // BIBLIOTECA PARA MANEJO DE ARCHIVOS XML
#include <openssl/evp.h>                    // BIBLIOTECA DE OPENSSL PARA CIFRADO/DECIFRADO
#include "common_crypto.h"                  // ARCHIVO DE CABECERA PROPIO PARA FUNCIONES CRIPTOGRÁFICAS
#include "logger.h"                         // ARCHIVO DE CABECERA PROPIO PARA REGISTRO DE EVENTOS
Logger logger;                              // INSTANCIA GLOBAL DEL LOGGER

#pragma comment(lib, "Ws2_32.lib")          // INDICA AL ENLAZADOR QUE USE LA LIBRERÍA Ws2_32

SOCKET sock;                                                          // VARIABLE GLOBAL PARA EL SOCKET DEL CLIENTE
std::vector<unsigned char> key(KEY_LEN), nonce(NONCE_LEN);            // CLAVE Y NONCE PARA CIFRADO
EVP_PKEY* client_keypair = nullptr;                                   // PUNTERO A LA PAREJA DE CLAVES DEL CLIENTE
int client_id = -1;                                                   // ID DEL CLIENTE, INICIALMENTE SIN ASIGNAR

std::string current_timestamp();            // DECLARACIÓN DE FUNCIÓN PARA OBTENER FECHA Y HORA ACTUAL

void banner_cliente() {
    // FUNCIÓN QUE MUESTRA UN BANNER ESTÉTICO AL INICIAR EL CLIENTE
    std::cout << "▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄\n";
    std::cout << "█─▄▄▄─█▄─▄███▄─▄█▄─▄▄─█▄─▀█▄─▄█─▄─▄─█\n";
    std::cout << "█─███▀██─██▀██─███─▄█▀██─█▄▀─████─███\n";
    std::cout << "█▄▄▄▄▄█▄▄▄▄▄█▄▄▄█▄▄▄▄▄█▄▄▄██▄▄██▄▄▄██\n\n";
    std::cout << "\nDeveloped by @marichu_kt\n";
    std::cout << "GitHub: https://github.com/marichu-kt\n";
    std::cout << "Type 'help' to see available commands.\n\n";
}

bool load_config(std::string& ip, int& port, const std::string& configPath) {
    // FUNCIÓN QUE CARGA LA CONFIGURACIÓN DEL ARCHIVO XML
    tinyxml2::XMLDocument doc;
    if (doc.LoadFile(configPath.c_str()) != tinyxml2::XML_SUCCESS) return false;
    auto* root = doc.FirstChildElement("config");
    if (!root) return false;
    ip = root->FirstChildElement("ip")->GetText();
    port = std::stoi(root->FirstChildElement("port")->GetText());
    return true;
}

void send_packet(const std::vector<unsigned char>& data) {
    // FUNCIÓN QUE ENVÍA UN PAQUETE DE DATOS AL SERVIDOR
    uint32_t len = static_cast<uint32_t>(data.size()); // LONGITUD DEL MENSAJE
    uint32_t len_net = htonl(len);                     // CONVERSIÓN A FORMATO DE RED
    send(sock, (char*)&len_net, 4, 0);                 // ENVÍA LA LONGITUD
    send(sock, (char*)data.data(), len, 0);            // ENVÍA LOS DATOS
}

void send_encrypted_file(const std::string& path) {
    // FUNCIÓN QUE LEE UN ARCHIVO, LO CIFRA Y LO ENVÍA AL SERVIDOR

    std::ifstream file(path, std::ios::binary);        // ABRE EL ARCHIVO EN MODO BINARIO
    if (!file.is_open()) {
        std::cerr << "[!] No se pudo abrir el archivo: " << path << "\n"; // ERROR SI NO SE PUEDE ABRIR
        return;
    }

    std::string filename = std::filesystem::path(path).filename().string(); // EXTRAER NOMBRE DEL ARCHIVO
    file.seekg(0, std::ios::end);                       // IR AL FINAL PARA OBTENER TAMAÑO
    std::streamsize size = file.tellg();                // TAMAÑO TOTAL DEL ARCHIVO
    file.seekg(0, std::ios::beg);                       // VOLVER AL INICIO

    std::vector<unsigned char> filedata(size);          // RESERVA DE MEMORIA PARA LOS DATOS
    file.read((char*)filedata.data(), size);            // LECTURA DEL CONTENIDO DEL ARCHIVO

    // === CONSTRUIR PAYLOAD TOTALMENTE CIFRADO ===
    std::vector<unsigned char> payload;

    // INCLUIR ID DEL CLIENTE (4 BYTES)
    payload.push_back((client_id >> 24) & 0xFF);
    payload.push_back((client_id >> 16) & 0xFF);
    payload.push_back((client_id >> 8) & 0xFF);
    payload.push_back(client_id & 0xFF);

    // LONGITUD DEL NOMBRE DEL ARCHIVO (4 BYTES)
    uint32_t name_len = static_cast<uint32_t>(filename.size());
    for (int i = 3; i >= 0; --i)
        payload.push_back((name_len >> (i * 8)) & 0xFF);

    // NOMBRE DEL ARCHIVO
    payload.insert(payload.end(), filename.begin(), filename.end());

    // TAMAÑO DEL ARCHIVO (8 BYTES)
    uint64_t filesize = static_cast<uint64_t>(size);
    for (int i = 7; i >= 0; --i)
        payload.push_back((filesize >> (i * 8)) & 0xFF);

    // CONTENIDO DEL ARCHIVO
    payload.insert(payload.end(), filedata.begin(), filedata.end());

    // === CIFRADO COMPLETO DEL PAYLOAD ===
    std::vector<unsigned char> tag;
    auto encrypted = encrypt(payload, key, nonce, tag); // CIFRADO AUTENTICADO CON ChaCha20-Poly1305

    // PREFIJAR CON UN TIPO GENÉRICO NO REVELADOR (EJ. 0xAA)
    std::vector<unsigned char> final_payload = { 0xAA };
    final_payload.insert(final_payload.end(), encrypted.begin(), encrypted.end());
    final_payload.insert(final_payload.end(), tag.begin(), tag.end());

    send_packet(final_payload);                         // ENVÍA EL PAQUETE CIFRADO

    std::cout << "[*] Archivo enviado: " << filename << " (" << filesize << " bytes)\n"; // CONFIRMACIÓN EN CONSOLA
}

bool read_loop() {
    std::vector<unsigned char> buffer;                       // BUFFER PARA ALMACENAR LOS DATOS RECIBIDOS
    while (true) {
        unsigned char header[4];                             // CABECERA DE 4 BYTES PARA LA LONGITUD DEL MENSAJE
        int received = recv(sock, (char*)header, 4, MSG_WAITALL); // RECIBE EXACTAMENTE 4 BYTES DE LA CABECERA
        if (received != 4) return false;                     // SI NO SE RECIBEN 4 BYTES, SE CIERRA EL BUCLE

        uint32_t msg_len = ntohl(*(uint32_t*)header);        // CONVIERTE LA LONGITUD A FORMATO DE HOST
        if (msg_len == 0) continue;                          // SI LA LONGITUD ES CERO, SE CONTINÚA AL SIGUIENTE CICLO

        buffer.resize(msg_len);                              // SE REDIMENSIONA EL BUFFER PARA EL MENSAJE COMPLETO
        received = recv(sock, (char*)buffer.data(), msg_len, MSG_WAITALL); // SE RECIBE EL MENSAJE COMPLETO
        if (received != msg_len) return false;               // SI NO SE RECIBE TODO, SE SALE CON FALLO

        std::vector<unsigned char> ciphertext(buffer.begin(), buffer.end() - TAG_LEN); // EXTRAE EL TEXTO CIFRADO
        std::vector<unsigned char> tag(buffer.end() - TAG_LEN, buffer.end());          // EXTRAE EL TAG DE AUTENTICACIÓN

        try {
            auto decrypted = decrypt(ciphertext, key, nonce, tag); // DESCIFRA EL MENSAJE USANDO LA CLAVE Y NONCE
            if (decrypted.empty()) continue;                 // SI LA SALIDA ESTÁ VACÍA, SE OMITE

            unsigned char type = decrypted[0];               // EL PRIMER BYTE INDICA EL TIPO DE MENSAJE

            if (type == 0x01) {                              // MENSAJE DE TEXTO DEL SERVIDOR
                std::string msg(decrypted.begin() + 1, decrypted.end()); // CONSTRUYE EL MENSAJE SIN EL BYTE TIPO
                std::cout << "\n" << current_timestamp() << " [Servidor] " << msg << "\n";
            }

            else if (type == 0x02) {                         // INDICADOR DE ARCHIVO RECIBIDO (SIN GUARDARLO)
                std::cout << "[*] Archivo recibido (no guardado en cliente).\n";
            }

            else if (type == 0x03) {                         // MENSAJE PRIVADO DE OTRO CLIENTE
                if (decrypted.size() < 5) continue;          // VERIFICA QUE HAYA SUFICIENTES BYTES
                uint32_t sender_id = 0;                      // INICIALIZA ID DEL REMITENTE
                for (int i = 0; i < 4; ++i)                  // RECONSTRUYE EL ID DEL REMITENTE (4 BYTES)
                    sender_id = (sender_id << 8) | decrypted[i + 1];
                std::string msg(decrypted.begin() + 5, decrypted.end()); // EXTRAE EL MENSAJE
                logger.log("Cliente", sender_id, msg);       // REGISTRA EN EL LOG
                std::cout << "\n" << current_timestamp() << " [Cliente " << sender_id << "] " << msg << "\n";
            }

            else if (type == 0x04) {                         // MENSAJE DE DIFUSIÓN (BROADCAST)
                std::string msg(decrypted.begin() + 1, decrypted.end()); // EXTRAER MENSAJE
                logger.log("Broadcast", client_id, msg);     // REGISTRAR EN EL LOG COMO BROADCAST
                std::cout << "\n" << current_timestamp() << " [Broadcast] " << msg << "\n";
            }

            else if (type == 0xFF) {                         // CÓDIGO DE APAGADO DEL SERVIDOR
                std::cout << "\n[!] Server is shutting down. Closing client...\n";
                closesocket(sock);                           // CIERRA EL SOCKET
                WSACleanup();                                // LIMPIA LA LIBRERÍA WINSOCK
                exit(0);                                     // TERMINA EL PROCESO
            }

            std::cout << "mario@client[" << client_id << "]:~$ "; // MUESTRA EL PROMPT NUEVAMENTE
            std::cout.flush();                               // VACÍA EL BUFFER DE SALIDA

        } catch (const std::exception& e) {                  // CAPTURA CUALQUIER EXCEPCIÓN DURANTE EL DESCIFRADO
            std::cerr << "\n[!] Error de descifrado: " << e.what() << "\n";
        }
    }
}


bool write_loop() {
    while (true) {
        std::cout << "mario@client[" << client_id << "]:~$ ";    // MUESTRA EL PROMPT DEL CLIENTE
        std::cout.flush();                                       // LIMPIA EL BUFFER DE SALIDA
        std::string msg;
        std::getline(std::cin, msg);                             // LEE UNA LÍNEA DE LA ENTRADA ESTÁNDAR
        if (msg.empty()) continue;                               // SI ESTÁ VACÍO, CONTINÚA AL SIGUIENTE CICLO

        // COMANDO: HELP
        if (msg == "help") {
            std::cout << "\n  [ Secure Client Command Reference ]  \n";
            std::cout << "  help                   Display this command reference.\n";
            std::cout << "  file <path>            Send an encrypted file to the server.\n";
            std::cout << "  <message>              Send an encrypted message to the server.\n";
            std::cout << "  exit                   Disconnect and close the client.\n\n";
            continue;
        }

        // COMANDO: EXIT
        if (msg == "exit") {
            std::cout << "[*] Disconnecting from server...\n";
            closesocket(sock);                                   // CIERRA EL SOCKET
            WSACleanup();                                        // LIMPIA LA LIBRERÍA WINSOCK
            std::cout << "[*] Client closed successfully.\n";
            exit(0);                                             // TERMINA EL PROGRAMA
        }

        // COMANDO: FILE <RUTA>
        if (msg.rfind("file ", 0) == 0) {
            send_encrypted_file(msg.substr(5));                  // ENVÍA EL ARCHIVO CIFRADO
            continue;
        }

        // CUALQUIER OTRO MENSAJE
        logger.log("Cliente", client_id, msg);                   // REGISTRA EL MENSAJE EN EL LOG
        std::vector<unsigned char> payload;
        payload.push_back(0x01);                                 // TIPO DE MENSAJE 0x01 (TEXTO)
        payload.insert(payload.end(), msg.begin(), msg.end());  // AÑADE EL MENSAJE AL PAYLOAD

        std::vector<unsigned char> tag;
        auto encrypted = encrypt(payload, key, nonce, tag);      // CIFRA EL PAYLOAD CON ChaCha20
        encrypted.insert(encrypted.end(), tag.begin(), tag.end()); // AÑADE EL TAG
        send_packet(encrypted);                                  // ENVÍA EL PAQUETE CIFRADO
    }
}

std::string current_timestamp() {
    using namespace std::chrono;
    auto now = system_clock::now();                              // OBTIENE LA HORA ACTUAL
    auto itt = system_clock::to_time_t(now);                     // CONVIERTE A time_t
    auto tm = *std::localtime(&itt);                             // CONVIERTE A ESTRUCTURA DE FECHA
    auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000; // MILISEGUNDOS

    std::ostringstream oss;
    oss << "[" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S")        // FORMATEA LA FECHA Y HORA
        << "." << std::setw(3) << std::setfill('0') << ms.count() << "]";
    return oss.str();                                            // DEVUELVE LA MARCA DE TIEMPO
}

int main(int argc, char* argv[]) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {             // INICIA WINSOCK
        std::cerr << "[!] Error al iniciar Winsock.\n";
        return 1;
    }

    std::string ip;
    int port;
    std::string configPath = "../src/client.xml";               // RUTA POR DEFECTO AL ARCHIVO DE CONFIGURACIÓN
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg.rfind("--config=", 0) == 0)
            configPath = arg.substr(9);                          // OBTIENE LA RUTA PERSONALIZADA SI SE PROPORCIONA
    }

    if (!load_config(ip, port, configPath)) {                    // CARGA IP Y PUERTO DESDE ARCHIVO XML
        std::cerr << "[!] No se pudo cargar configuración desde " << configPath << "\n";
        return 1;
    }

    sockaddr_in serv_addr{};                                     // CONFIGURA LA DIRECCIÓN DEL SERVIDOR
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr.s_addr = inet_addr(ip.c_str());

    sock = socket(AF_INET, SOCK_STREAM, 0);                      // CREA EL SOCKET
    if (connect(sock, (SOCKADDR*)&serv_addr, sizeof(serv_addr)) != 0) {
        std::cerr << "[!] No se pudo conectar al servidor.\n";   // CONEXIÓN FALLIDA
        return 1;
    }

    banner_cliente();                                            // MUESTRA EL BANNER DE INICIO

    unsigned char server_pubkey[PUBKEY_LEN];                     // RECIBE LA CLAVE PÚBLICA DEL SERVIDOR
    recv(sock, (char*)server_pubkey, PUBKEY_LEN, MSG_WAITALL);

    client_keypair = generate_x25519_keypair();                  // GENERA PAR DE CLAVES X25519 DEL CLIENTE
    unsigned char client_pubkey[PUBKEY_LEN];
    get_public_key(client_pubkey, client_keypair);               // OBTIENE LA CLAVE PÚBLICA DEL CLIENTE
    send(sock, (char*)client_pubkey, PUBKEY_LEN, 0);             // ENVÍA LA CLAVE PÚBLICA AL SERVIDOR

    compute_shared_secret(key, client_keypair, server_pubkey);   // CALCULA LA CLAVE SECRETA COMPARTIDA
    recv(sock, (char*)nonce.data(), NONCE_LEN, MSG_WAITALL);     // RECIBE EL NONCE DEL SERVIDOR

    uint32_t net_id = 0;
    recv(sock, (char*)&net_id, sizeof(net_id), MSG_WAITALL);     // RECIBE EL ID DEL CLIENTE
    client_id = ntohl(net_id);                                   // CONVIERTE A FORMATO DE HOST

    std::thread(read_loop).detach();                             // INICIA EL HILO DE LECTURA EN PARALELO
    write_loop();                                                // EJECUTA EL BUCLE DE ESCRITURA

    closesocket(sock);                                           // CIERRA EL SOCKET AL TERMINAR
    WSACleanup();                                                // LIMPIA LOS RECURSOS DE WINSOCK
    return 0;                                                    // FIN DEL PROGRAMA
}
