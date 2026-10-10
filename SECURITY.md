# Seguridad

PQ Lab es una **herramienta de laboratorio**. No está pensada para custodiar claves de
producción ni para operar una autoridad de certificación real.

## Modelo de seguridad

- Toda la criptografía la realiza el binario `openssl` 3.5 empaquetado (sidecar). La
  aplicación no implementa criptografía.
- La base de datos guarda el hash Argon2id de la contraseña maestra, nunca la contraseña.
- Las claves privadas se guardan siempre como PKCS#8 cifrado (AES-256-CBC, PBKDF2)
  con la contraseña maestra. Una clave privada nunca se escribe en claro en disco, ni
  siquiera de forma temporal: las importaciones pasan la PEM por la entrada estándar
  de OpenSSL.
- Las contraseñas viajan a OpenSSL por la entrada estándar (`-pass stdin`), nunca por
  argumentos de línea de comandos, y no se registran.
- Cada operación usa un directorio temporal propio con permisos `0700`, que se borra
  al terminar (también si hay error).
- La contraseña maestra se borra de memoria (`zeroize`) al bloquear o cerrar.

## Limitaciones conocidas

- La protección de las claves depende de la fortaleza de la contraseña maestra.
- Hay revocación con CRL, pero no respondedor OCSP ni soporte de HSM.
- La base de datos SQLite no está cifrada entera: solo las claves privadas. Nombres,
  sujetos y certificados se pueden leer sin la contraseña maestra.
- `zeroize` borra la contraseña en el backend, pero no puede garantizar que no queden
  copias en la memoria de la interfaz web o de los procesos de OpenSSL.
- Si la aplicación termina de forma abrupta, puede quedar un directorio temporal (solo
  con material público o claves cifradas).
- Los instaladores no están firmados ni notarizados.

## Notificar una vulnerabilidad

No abras un *issue* público. Escribe a la persona mantenedora del repositorio por un
canal privado (aviso de seguridad privado de GitHub) con una descripción y, si es
posible, los pasos para reproducirla.
