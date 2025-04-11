#ifndef COMMON_CRYPTO_H
#define COMMON_CRYPTO_H

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <vector>
#include <string>
#include <stdexcept>

constexpr int KEY_LEN = 32;          // LONGITUD CLAVE 256 BITS ("LLAVE")
constexpr int NONCE_LEN = 12;        // LONGITUD NONCE 96 BITS ("NUMERO")
constexpr int TAG_LEN = 16;          // LONGITUD TAG 128 BITS ("ETIQUETA")

// GENERA CLAVE ALEATORIA
inline void generate_key(std::vector<unsigned char>& key) {
    key.resize(KEY_LEN);                                        // AJUSTA TAMAÑO
    if (!RAND_bytes(key.data(), KEY_LEN))                       // GENERA BYTES
        throw std::runtime_error("Error generando clave");      // ERROR
}

// GENERA NONCE ALEATORIO
inline void generate_nonce(std::vector<unsigned char>& nonce) {
    nonce.resize(NONCE_LEN);                                    // AJUSTA TAMAÑO
    if (!RAND_bytes(nonce.data(), NONCE_LEN))                   // GENERA BYTES
        throw std::runtime_error("Error generando nonce");      // ERROR
}

// CIFRA CON CHACHA20-POLY1305
inline std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext,
                                          const std::vector<unsigned char>& key,
                                          const std::vector<unsigned char>& nonce,
                                          std::vector<unsigned char>& tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();                                           // CREA CONTEXTO
    std::vector<unsigned char> ciphertext(plaintext.size());                              // SALIDA
    tag.resize(TAG_LEN);                                                                  // AJUSTA TAG

    int len;
    if (!EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL))             // INICIALIZA
        throw std::runtime_error("Error init");                                          // ERROR

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, NONCE_LEN, NULL);                  // SET NONCE LEN
    EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), nonce.data());                       // SET KEY/NONCE
    EVP_EncryptUpdate(ctx, NULL, &len, NULL, 0);                                         // SIN AAD
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()); // CIFRA
    int ciphertext_len = len;                                                            // GUARDA LONGITUD
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);                             // FINALIZA
    ciphertext_len += len;                                                               // ACTUALIZA
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag.data());                // OBTIENE TAG
    ciphertext.resize(ciphertext_len);                                                   // AJUSTA TAMAÑO
    EVP_CIPHER_CTX_free(ctx);                                                            // LIBERA CONTEXTO
    return ciphertext;                                                                   // RETORNA CIFRADO
}

// DESCIFRA CON CHACHA20-POLY1305
inline std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext,
                                          const std::vector<unsigned char>& key,
                                          const std::vector<unsigned char>& nonce,
                                          const std::vector<unsigned char>& tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();                // CREA CONTEXTO
    std::vector<unsigned char> plaintext(ciphertext.size());   // SALIDA

    int len;
    if (!EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL))              // INICIALIZA
        throw std::runtime_error("Error init");                                           // ERROR

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, NONCE_LEN, NULL);                   // SET NONCE LEN
    EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), nonce.data());                        // SET KEY/NONCE
    EVP_DecryptUpdate(ctx, NULL, &len, NULL, 0);                                          // SIN AAD
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()); // DESCIFRA
    int plaintext_len = len;                                                              // LONGITUD PARCIAL
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_LEN, (void*)tag.data());          // SET TAG

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) <= 0) { // VERIFICA TAG
        EVP_CIPHER_CTX_free(ctx);                                      // LIBERA CONTEXTO
        throw std::runtime_error("Error: autenticación fallida");      // FALLA AUTENTICACIÓN
    }

    plaintext_len += len;                                  // LONGITUD FINAL
    plaintext.resize(plaintext_len);                       // AJUSTA VECTOR
    EVP_CIPHER_CTX_free(ctx);                              // LIBERA CONTEXTO
    return plaintext;                                      // RETORNA TEXTO
}
#endif                                                     // FIN DE CABECERA