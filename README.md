# ChaCha20-Poly1305: Una Guía Completa

Bienvenido(a) a esta guía sobre ChaCha20-Poly1305, un **algoritmo de cifrado y autenticación** ampliamente utilizado en la actualidad. A lo largo de este documento, exploraremos en detalle qué es ChaCha20, cómo funciona internamente y por qué se combina con Poly1305 para formar un esquema de cifrado **AEAD (Authenticated Encryption with Associated Data)** seguro y eficiente.

## ¿Qué es ChaCha20?

ChaCha20 es un **cifrado de flujo** (stream cipher) diseñado por Daniel J. Bernstein. Se considera una variante mejorada del cifrado Salsa20, optimizada en términos de seguridad y rendimiento en diversas plataformas, incluyendo dispositivos móviles y entornos de bajo consumo energético.

### Orígenes y Motivación

- **Diseñador**: Daniel J. Bernstein, conocido por sus aportes en criptoanálisis y diseño de sistemas cifrados.
- **Objetivo**: Crear un cifrado de flujo altamente seguro, rápido y fácil de implementar en hardware y software, superando algunas debilidades y limitaciones de otros cifrados de flujo más antiguos.

### Poly1305

Poly1305 es un algoritmo de **autenticación de mensajes** (Message Authentication Code, MAC) también creado por Daniel J. Bernstein. Cuando se combina con ChaCha20, se obtiene ChaCha20-Poly1305, un modo de cifrado autenticado (AEAD) que no solo cifra los datos, sino que **garantiza su integridad** y la **autenticidad** de los mismos.

## Imágenes sugeridas

1. ![Estructura de la matriz de estado](estado.png) → "Una imagen que muestre una matriz de 4x4 con cada celda etiquetada como constante, clave, contador y nonce".
2. ![Quarter Round](quarter-round.png) → "Un diagrama paso a paso mostrando cómo se transforma un bloque de 4 palabras en una quarter round".
3. ![Transformación de estado en una double round](transformacion-ronda.png) → "Una representación visual de cómo la matriz cambia durante una double round".

## Referencias

- Bernstein, D. J. (2008). *ChaCha, a variant of Salsa20*.
- Bernstein, D. J. (2005). *The Poly1305-AES message-authentication code*.
- IETF RFC 8439: [ChaCha20 and Poly1305 for IETF Protocols](https://datatracker.ietf.org/doc/html/rfc8439)
- IETF RFC 8446: [TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
