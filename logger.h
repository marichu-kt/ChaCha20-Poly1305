#ifndef LOGGER_H
#define LOGGER_H

#include <fstream>                          // BIBLIOTECA PARA MANEJO DE ARCHIVOS
#include <string>                           // BIBLIOTECA PARA MANEJO DE STRINGS
#include <mutex>                            // BIBLIOTECA PARA CONTROL DE CONCURRENCIA
#include <chrono>                           // BIBLIOTECA PARA OBTENER FECHA Y HORA
#include <iomanip>                          // BIBLIOTECA PARA FORMATEAR FECHA Y HORA
#include <sstream>                          // BIBLIOTECA PARA CONVERTIR A STRING
#include <filesystem>                       // AÑADIDO PARA CREAR LA CARPETA LOGS AUTOMÁTICAMENTE

class Logger {
private:
    std::ofstream file;                     // ARCHIVO DE SALIDA PARA LOS LOGS
    std::mutex log_mutex;                   // MUTEX PARA PROTEGER ACCESO CONCURRENTE AL ARCHIVO

    // FUNCIÓN PARA OBTENER LA MARCA DE TIEMPO ACTUAL CON PRECISIÓN DE MILISEGUNDOS
    std::string current_timestamp() {
        using namespace std::chrono;
        auto now = system_clock::now();                                 // OBTIENE TIEMPO ACTUAL
        auto itt = system_clock::to_time_t(now);                        // CONVIERTE A FORMATO TIME_T
        auto tm = *std::localtime(&itt);                                // CONVIERTE A ESTRUCTURA DE TIEMPO
        auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000; // CALCULA MILISEGUNDOS

        std::ostringstream oss;
        oss << "[" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S")           // FORMATEA LA FECHA Y HORA
            << "." << std::setw(3) << std::setfill('0') << ms.count() << "]";
        return oss.str();                                               // DEVUELVE LA MARCA DE TIEMPO FORMATEADA
    }

public:
    // CONSTRUCTOR QUE ABRE EL ARCHIVO DE LOG EN MODO APPEND Y CREA LA CARPETA SI NO EXISTE
    Logger(const std::string& filename = "../logs/communications_history.log") {
        std::filesystem::create_directories("../logs");                // CREA LA CARPETA LOGS SI NO EXISTE
        file.open(filename, std::ios::app);                            // ABRE EL ARCHIVO EN MODO AÑADIR
    }

    // DESTRUCTOR QUE CIERRA EL ARCHIVO SI ESTÁ ABIERTO
    ~Logger() {
        if (file.is_open()) file.close();
    }

    // FUNCIÓN PARA REGISTRAR UN MENSAJE EN EL LOG CON IDENTIFICADOR Y ORIGEN
    void log(const std::string& source, int id, const std::string& message) {
        std::lock_guard<std::mutex> lock(log_mutex);                   // BLOQUEO PARA ACCESO EXCLUSIVO
        if (file.is_open()) {
            file << current_timestamp()                                // ESCRIBE LA FECHA Y HORA
                 << " [" << source << " " << id << "] "                // ESCRIBE EL ORIGEN E ID
                 << message << std::endl;                              // ESCRIBE EL MENSAJE
        }
    }
};

#endif // LOGGER_H
