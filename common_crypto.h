
#ifndef COMMON_CRYPTO_H
#define COMMON_CRYPTO_H

#include <openssl/evp.h>                   // BIBLIOTECA DE OPENSSL PARA FUNCIONES CRIPTOGRÁFICAS
#include <openssl/rand.h>                  // BIBLIOTECA DE OPENSSL PARA GENERAR DATOS ALEATORIOS
#include <vector>                          // BIBLIOTECA DE VECTORES DINÁMICOS
#include <string>                          // BIBLIOTECA PARA MANEJO DE STRINGS
#include <stdexcept>                       // BIBLIOTECA PARA LANZAR EXCEPCIONES

constexpr int KEY_LEN = 32;               // LONGITUD DE CLAVE PARA CHACHA20-POLY1305 (256 BITS)
constexpr int NONCE_LEN = 12;             // LONGITUD DEL NONCE PARA CHACHA20-POLY1305
constexpr int TAG_LEN = 16;               // LONGITUD DEL TAG DE AUTENTICACIÓN
constexpr int PUBKEY_LEN = 32;            // LONGITUD DE CLAVE PÚBLICA X25519

// ===================== CLAVES X25519 =====================

// GENERA PAR DE CLAVES X25519 (TEMPORAL EN MEMORIA)
inline EVP_PKEY* generate_x25519_keypair() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Error inicializando generación de clave X25519");
    }

    EVP_PKEY* keypair = nullptr;
    if (EVP_PKEY_keygen(ctx, &keypair) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Error generando clave X25519");
    }

    EVP_PKEY_CTX_free(ctx);
    return keypair;
}

// DERIVA CLAVE COMPARTIDA USANDO CLAVE LOCAL Y CLAVE PÚBLICA DEL PEER
inline void compute_shared_secret(std::vector<unsigned char>& shared_key,
                                  EVP_PKEY* local_keypair,
                                  const unsigned char* peer_pubkey) {
    EVP_PKEY* peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pubkey, PUBKEY_LEN);
    if (!peer_key) throw std::runtime_error("Error creando clave pública remota");

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(local_keypair, NULL);
    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0 || EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) {
        EVP_PKEY_free(peer_key);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Error configurando derivación de clave");
    }

    size_t secret_len;
    EVP_PKEY_derive(ctx, NULL, &secret_len);                      // OBTIENE LA LONGITUD DE LA CLAVE DERIVADA
    shared_key.resize(secret_len);
    if (!EVP_PKEY_derive(ctx, shared_key.data(), &secret_len)) {  // DERIVA LA CLAVE COMPARTIDA
        EVP_PKEY_free(peer_key);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Error derivando clave compartida");
    }

    EVP_PKEY_free(peer_key);
    EVP_PKEY_CTX_free(ctx);
}

// OBTIENE LA CLAVE PÚBLICA DE UN PAR DE CLAVES X25519
inline void get_public_key(unsigned char* out_pubkey, EVP_PKEY* keypair) {
    size_t len = PUBKEY_LEN;
    if (!EVP_PKEY_get_raw_public_key(keypair, out_pubkey, &len)) {
        throw std::runtime_error("Error obteniendo clave pública local");
    }
}

// ===================== NONCE =====================

// GENERA UN NONCE ALEATORIO DE 12 BYTES
inline void generate_nonce(std::vector<unsigned char>& nonce) {
    nonce.resize(NONCE_LEN);
    if (!RAND_bytes(nonce.data(), NONCE_LEN))
        throw std::runtime_error("Error generando nonce");
}

// ===================== CIFRAR =====================

// CIFRA UN MENSAJE CON CHACHA20-POLY1305
inline std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext,
                                          const std::vector<unsigned char>& key,
                                          const std::vector<unsigned char>& nonce,
                                          std::vector<unsigned char>& tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Error creando contexto de cifrado");

    std::vector<unsigned char> ciphertext(plaintext.size());
    tag.resize(TAG_LEN);
    int len;

    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);        // INICIALIZA CIFRADO
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, NONCE_LEN, nullptr);             // CONFIGURA LONGITUD DEL NONCE
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data());               // ESTABLECE CLAVE Y NONCE

    EVP_EncryptUpdate(ctx, nullptr, &len, nullptr, 0);                                  // INICIO DE CIFRADO (SIN DATOS)
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()); // CIFRA LOS DATOS
    int ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);                            // FINALIZA EL CIFRADO
    ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag.data());               // OBTIENE EL TAG DE AUTENTICACIÓN
    EVP_CIPHER_CTX_free(ctx);                                                           // LIBERA EL CONTEXTO

    ciphertext.resize(ciphertext_len);                                                  // AJUSTA EL TAMAÑO DEL RESULTADO
    return ciphertext;
}

// ===================== DESCIFRAR =====================

// DESCIFRA UN MENSAJE CON CHACHA20-POLY1305 Y VERIFICA EL TAG
inline std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext,
                                          const std::vector<unsigned char>& key,
                                          const std::vector<unsigned char>& nonce,
                                          const std::vector<unsigned char>& tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Error creando contexto de descifrado");

    std::vector<unsigned char> plaintext(ciphertext.size());
    int len;

    EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);        // INICIALIZA DESCIFRADO
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, NONCE_LEN, nullptr);             // CONFIGURA LONGITUD DEL NONCE
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data());               // ESTABLECE CLAVE Y NONCE

    EVP_DecryptUpdate(ctx, nullptr, &len, nullptr, 0);                                  // INICIO DE DESCIFRADO (SIN DATOS)
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()); // DESCIFRA LOS DATOS
    int plaintext_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_LEN, (void*)tag.data());        // ESTABLECE EL TAG PARA VERIFICAR

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) <= 0) {                  // VERIFICA Y FINALIZA EL DESCIFRADO
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Error: autenticación fallida");                       // SI EL TAG NO COINCIDE, ERROR
    }

    plaintext_len += len;
    plaintext.resize(plaintext_len);                                                    // AJUSTA TAMAÑO DEL TEXTO PLANO
    EVP_CIPHER_CTX_free(ctx);                                                           // LIBERA EL CONTEXTO
    return plaintext;
}

#endif // COMMON_CRYPTO_H
