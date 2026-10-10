# PQ Lab

**Gestor de claves y certificados X.509 post-cuánticos para entornos de laboratorio.**

PQ Lab es una aplicación de escritorio, al estilo de [XCA](https://hohnstaedt.de/xca/),
para crear y administrar PKIs de prueba usando exclusivamente los algoritmos
post-cuánticos estandarizados por el NIST: **ML-DSA** (FIPS 204), **SLH-DSA**
(FIPS 205) y **ML-KEM** (FIPS 203). Toda la criptografía la realiza
**OpenSSL 3.5**, que se distribuye dentro de la propia aplicación.

> [!WARNING]
> **Solo para laboratorio, docencia y pruebas de interoperabilidad.** PQ Lab no es una
> autoridad de certificación de producción ni ha pasado una auditoría de seguridad
> externa. No la uses para proteger sistemas reales.

![Licencia](https://img.shields.io/badge/licencia-Apache--2.0-blue)
![Versión](https://img.shields.io/badge/versión-0.2.0-informational)
![OpenSSL](https://img.shields.io/badge/OpenSSL-3.5.9-green)

---

## Índice

- [Características](#características)
- [Algoritmos soportados](#algoritmos-soportados)
- [Cómo funciona](#cómo-funciona)
- [Seguridad](#seguridad)
- [Instalación](#instalación)
- [Compilar desde el código fuente](#compilar-desde-el-código-fuente)
- [Guía rápida](#guía-rápida)
- [Desarrollo y tests](#desarrollo-y-tests)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Estado y limitaciones](#estado-y-limitaciones)
- [Licencia](#licencia)

---

## Características

| Área | Qué permite |
|------|-------------|
| **Claves** | Generar los 18 tipos de clave PQ; importar PEM (en claro, cifrada o solo pública); renombrar; borrar; exportar la pública y la privada (siempre cifrada). |
| **Certificados** | Raíces autofirmadas, CAs intermedias y certificados finales firmados por cualquier CA de la base de datos, con validez por días o por fechas exactas. |
| **Editor de extensiones** | basicConstraints (CA, *pathlen*, crítica), keyUsage y extendedKeyUsage (con OIDs propios y marca de crítica), SKI/AKI, SAN (DNS, IP, correo, URI), políticas, puntos de distribución de CRL, AIA (OCSP y emisor de CA) y nameConstraints. |
| **Plantillas** | 10 predefinidas (CA raíz, CA intermedia, servidor TLS, cliente TLS, servidor + cliente, firma de código, S/MIME, sellado de tiempo, firmante OCSP, ML-KEM) y plantillas propias. |
| **CSR** | Generar peticiones desde una clave propia con extensiones solicitadas; importar peticiones externas (se verifica su firma) y firmarlas con una CA. |
| **Revocación** | Revocar con motivo RFC 5280, anular la revocación y generar, ver y exportar CRLs (PEM/DER). |
| **Renovación** | Reemitir un certificado con el mismo sujeto, clave y extensiones, con nuevo número de serie y validez. |
| **PKCS#12** | Exportar certificado + clave (+ cadena) e importar `.p12`. |
| **Verificación** | Verificar la cadena completa hasta la raíz, teniendo en cuenta las revocaciones y las CRLs de todos los emisores. |
| **Exportación** | Certificado (PEM/DER), cadena completa (PEM), clave pública, CRL y PKCS#12. |
| **Interfaz** | Aplicación de escritorio clásica: menú nativo, listas densas con columna de botones, vista en árbol de la jerarquía de CAs, diálogos con pestañas, tema claro y oscuro. |

La base de datos es un **único fichero SQLite** protegido con una contraseña maestra.
Se puede copiar a otro equipo y abrir allí con la misma contraseña, igual que un `.xdb`
de XCA.

## Algoritmos soportados

| Familia | Estándar | Variantes | Firma | Puede ser CA |
|---------|----------|-----------|:-----:|:------------:|
| ML-DSA | FIPS 204 | ML-DSA-44, ML-DSA-65, ML-DSA-87 | ✓ | ✓ |
| SLH-DSA | FIPS 205 | SHA2 y SHAKE; 128, 192 y 256 bits; variantes `s` (pequeña) y `f` (rápida): 12 en total | ✓ | ✓ |
| ML-KEM | FIPS 203 | ML-KEM-512, ML-KEM-768, ML-KEM-1024 | ✗ | ✗ |

Las claves, certificados y peticiones con algoritmos clásicos (RSA, ECDSA, EdDSA) se
rechazan al importarlos.

### Reglas X.509 específicas de PQ

PQ Lab aplica reglas que una herramienta genérica no impone. Así se evita crear
certificados PQ incorrectos:

- **keyUsage según el algoritmo** (RFC 9881 y RFC 9909):
  - ML-DSA y SLH-DSA admiten `digitalSignature`, `nonRepudiation`, `keyCertSign` y `cRLSign`.
  - ML-KEM admite únicamente `keyEncipherment`.
- **keyCertSign ⇔ CA**: solo las CAs pueden firmar certificados, y toda CA debe poder hacerlo.
- **ML-KEM** no puede firmar. Por tanto:
  - No puede ser CA, autofirmarse ni generar una CSR.
  - Su certificado lo emite una CA directamente a partir de la clave pública
    (`openssl x509 -new -force_pubkey`).
- **Sin digest separado**: las firmas ML-DSA y SLH-DSA no llevan `-sha256` ni similares.
- **Coherencia de la jerarquía**:
  - Se respeta el `pathlen` de todas las CAs superiores.
  - La validez de un certificado se recorta a la de su emisor.
  - Un certificado de servidor TLS exige al menos un SAN.

## Cómo funciona

```
┌──────────────────────────── Ventana de escritorio (Tauri v2) ───────────────────────────┐
│                                                                                         │
│  Interfaz (React + TypeScript)                                                          │
│  Listas, diálogos, editor de extensiones. Solo ofrece opciones válidas para cada clave. │
│                     │                                                                   │
│                     │  IPC de Tauri (comandos con JSON)                                 │
│                     ▼                                                                   │
│  Núcleo (Rust)                                                                          │
│  · Valida todas las entradas y reglas PQ antes de llamar a OpenSSL                      │
│  · Genera ficheros de configuración temporales a partir de listas blancas               │
│  · Guarda claves cifradas, certificados, CSRs y CRLs en SQLite                          │
│  · No implementa criptografía: solo orquesta                                            │
│                     │                                                                   │
│                     │  proceso hijo; contraseñas por stdin                              │
│                     ▼                                                                   │
│  openssl 3.5 (binario estático incluido en la aplicación)                               │
│  genpkey · req · x509 · ca -gencrl · verify · pkcs12 · crl                              │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

Una operación típica, como emitir un certificado firmado por una CA, sigue estos pasos:

1. La interfaz envía la petición (clave, emisor, sujeto, perfil de extensiones y validez).
2. El núcleo comprueba que la base de datos está desbloqueada y valida la petición:
   - el algoritmo de la clave frente al keyUsage pedido;
   - que el emisor sea una CA vigente, no revocada y con clave privada;
   - el `pathlen`, los SAN y las fechas.
3. Se crea un directorio temporal privado. En él se escriben solo material público,
   claves privadas **cifradas** y un `ext.cnf` generado a partir del perfil validado.
4. Se ejecuta `openssl` con un número de serie aleatorio de 128 bits. Las contraseñas
   van por la entrada estándar.
5. El resultado se analiza con `openssl x509 -text` y se guarda en la base de datos.
6. El directorio temporal se borra, también si la operación falla.

**Directorio de datos.** La base de datos se crea por defecto en el directorio de datos
del usuario:

| Sistema | Directorio por defecto |
|---------|------------------------|
| macOS | `~/Library/Application Support/dev.pqlab.app/` |
| Windows | `%APPDATA%\dev.pqlab.app\` |
| Linux | `~/.local/share/dev.pqlab.app/` |

Si junto al ejecutable existe una carpeta `pqlab-data`, se usa esa (modo portable).

## Seguridad

- **Contraseña maestra.** Solo se guarda su hash Argon2id. En memoria se mantiene en un
  tipo que se borra (`zeroize`) al bloquear o cerrar la base de datos.
- **Claves privadas siempre cifradas.**
  - Se guardan como PKCS#8 cifrado con AES-256 y la contraseña maestra.
  - Una clave privada nunca existe en claro en disco, ni siquiera de forma temporal.
  - Las importaciones en claro se pasan a OpenSSL por la entrada estándar.
- **Contraseñas fuera de la línea de comandos.** Se entregan a OpenSSL por stdin y no
  aparecen en argumentos, registros ni mensajes de error.
- **Ficheros temporales.** Cada operación usa su propio directorio con permisos `0700`,
  que se borra al terminar.
- **Sin inyección en la configuración.** Todo valor de usuario pasa por listas blancas
  de caracteres antes de llegar a un fichero de configuración de OpenSSL.

Limitaciones conocidas y forma de notificar vulnerabilidades: [SECURITY.md](SECURITY.md).

## Instalación

Si hay paquetes publicados en *Releases*, descarga el de tu sistema:

| Sistema | Paquete | Uso |
|---------|---------|-----|
| Windows 10/11 x64 | `PQ-Lab-<versión>-Windows-x64-portable.zip` | Descomprimir y doble clic en `PQ Lab.exe`. Los datos quedan en `pqlab-data`, junto al ejecutable. |
| Windows 10/11 x64 | `PQ-Lab-<versión>-Windows-x64-setup.exe` | Instalador por usuario, sin permisos de administrador. |
| macOS 11+ (Apple Silicon e Intel) | `PQ-Lab-<versión>-macOS-universal.dmg` | Arrastrar *PQ Lab* a Aplicaciones. |
| Linux x86_64 | `PQ-Lab-<versión>-Linux-x86_64.AppImage` | `chmod +x` y ejecutar. |
| Debian / Ubuntu | `PQ-Lab-<versión>-Linux-amd64.deb` | `sudo apt install ./PQ-Lab-<versión>-Linux-amd64.deb` |

No hace falta tener OpenSSL instalado: cada paquete incluye su propio OpenSSL 3.5.9.

- **Binarios sin firmar.** En macOS, la primera vez abre la app con clic derecho →
  *Abrir*. En Windows, si SmartScreen avisa, pulsa *Más información* → *Ejecutar de
  todas formas*.
- **Windows.** Necesita Microsoft Edge WebView2, incluido en Windows 11 y en los Windows
  10 actualizados. El instalador lo descarga si falta; la versión portable no.
- **Linux.** Necesita WebKitGTK 4.1; el paquete `.deb` lo instala como dependencia.

Cada release incluye `SHA256SUMS.txt` para comprobar los ficheros descargados.

## Compilar desde el código fuente

Cualquiera puede compilar PQ Lab en su equipo. El proceso:
- descarga y compila OpenSSL 3.5.9 (versión y SHA-256 fijados en el script);
- compila la aplicación;
- genera el instalador del sistema en el que se compila.

### Requisitos

| Herramienta | Versión |
|-------------|---------|
| [Rust](https://rustup.rs) | stable (≥ 1.85) |
| [Node.js](https://nodejs.org) | 22 LTS |
| `perl`, `make` y un compilador de C | para compilar OpenSSL |

Además, según el sistema:

- **macOS:** Xcode Command Line Tools (`xcode-select --install`).
- **Linux (Debian/Ubuntu):**
  ```bash
  sudo apt install build-essential perl libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf
  ```
- **Windows (compilación nativa):** Visual Studio Build Tools (C++), Strawberry Perl y
  Git Bash, para ejecutar los scripts.

Necesitas unos 10 GB libres: las compilaciones intermedias de Rust ocupan mucho. El
resultado final ocupa unos 20 MB.

### Pasos

```bash
git clone https://github.com/MarcosPerezCantero/pq-lab.git
cd pq-lab

./scripts/build-openssl.sh      # OpenSSL 3.5.9 → src-tauri/binaries/ (unos minutos)
npm ci                          # dependencias de la interfaz

npm run tauri dev               # ejecutar en modo desarrollo
npm run tauri build             # o generar el instalador del sistema actual
```

El instalador queda en `src-tauri/target/release/bundle/`.

### Compilación cruzada desde macOS (Mac universal + Windows)

```bash
brew install mingw-w64 makensis
rustup target add aarch64-apple-darwin x86_64-apple-darwin x86_64-pc-windows-gnu

TARGET_TRIPLE=universal-apple-darwin ./scripts/build-openssl.sh
TARGET_TRIPLE=x86_64-pc-windows-gnu  ./scripts/build-openssl.sh

npm run tauri build -- --target universal-apple-darwin
npm run tauri build -- --target x86_64-pc-windows-gnu --bundles nsis

./scripts/package-release.sh    # deja los paquetes y SHA256SUMS.txt en dist-release/
```

### Releases automáticas

Al subir una etiqueta `v*` (por ejemplo `git tag v0.2.0 && git push origin v0.2.0`), el
workflow [`release.yml`](.github/workflows/release.yml) compila los paquetes de macOS,
Windows y Linux en GitHub Actions. Después crea una *release* en borrador con todos
ellos y sus sumas SHA-256.

### Variables de entorno

| Variable | Uso |
|----------|-----|
| `PQLAB_OPENSSL` | Ruta a otro binario `openssl` (≥ 3.5) en lugar del incluido. |
| `PQLAB_DATA_DIR` | Directorio de datos alternativo. |

## Guía rápida

1. Al abrir la aplicación, crea una base de datos y elige una **contraseña maestra**. Si
   la pierdes, no hay forma de recuperar las claves.
2. **Certificados → Nueva CA raíz**: por ejemplo, ML-DSA-87.
3. Con la raíz seleccionada, **Nueva CA intermedia**: por ejemplo, ML-DSA-65.
4. Con la intermedia seleccionada, **Nuevo certificado**:
   - plantilla *Servidor TLS*, con un SAN `DNS:servidor.lab`; o
   - plantilla *Cifrado ML-KEM*, para un certificado de clave ML-KEM-768.
5. **Exportar… → Cadena completa** y comprueba la cadena con cualquier OpenSSL ≥ 3.5:

   ```bash
   openssl verify -CAfile raiz.pem -untrusted cadena.pem cadena.pem
   ```

6. Para probar la revocación:
   1. Selecciona un certificado y pulsa **Revocar**.
   2. En **Revocaciones → Generar CRL**, genera la CRL de su emisor.
   3. Comprueba que el certificado se rechaza:

      ```bash
      openssl verify -crl_check -CRLfile emisor.crl -CAfile raiz.pem -untrusted inter.pem hoja.pem
      ```

Atajos: `Ctrl/⌘+K` nueva clave, `Ctrl/⌘+N` nuevo certificado, `Ctrl/⌘+I` importar,
`Ctrl/⌘+L` bloquear la base de datos.

## Desarrollo y tests

Los tests de integración usan el **OpenSSL real** y comprueban cada resultado de forma
independiente. Para ello ejecutan `openssl verify`, `x509 -text`, `crl -verify` o
`pkcs12` sobre ficheros exportados a un directorio limpio.

```bash
cd src-tauri
cargo test                                  # 69 tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cd ..
npm run lint
npm run build
```

| Fichero de tests | Cubre |
|------------------|-------|
| `phase0_openssl.rs` | Versión de OpenSSL, catálogo de algoritmos, certificado ML-KEM |
| `keys.rs` | Los 18 tipos de clave; importación y exportación |
| `chains.rs` | Raíces, cadenas mixtas ML-DSA/SLH-DSA/ML-KEM, exportación y renovación |
| `csr.rs` | CSR externas, CSR manipuladas, extensiones solicitadas |
| `extensions.rs` | Cada extensión llega al certificado; nameConstraints aplicadas; plantillas propias |
| `validation_rules.rs` | Reglas PQ, SAN obligatorio, *pathlen*, fechas, base de datos bloqueada |
| `revocation.rs` | CRLs, verificación con revocaciones en toda la cadena, borrado de certificados revocados |
| `pkcs12.rs` | Exportación, lectura con OpenSSL externo, importación atómica |
| `security.rs` | Sin claves en claro en disco, temporales borrados, contraseñas fuera de los registros |
| `ui_e2e.rs` | Cadena completa a través de los mismos comandos que usa la interfaz |

El workflow [`ci.yml`](.github/workflows/ci.yml) ejecuta todo lo anterior en cada *push*
y *pull request*.

## Estructura del proyecto

```
├── src/                     Interfaz (React + TypeScript)
│   ├── api.ts               Llamadas tipadas al núcleo
│   ├── components/          Lista con árbol, editor de extensiones, selector de claves
│   ├── dialogs/             Diálogos de certificados, claves, CSR, CRL y plantillas
│   ├── views/               Pestañas principales y pantalla de desbloqueo
│   └── i18n/es.json         Textos de la interfaz y mensajes de error
├── src-tauri/               Núcleo (Rust)
│   ├── src/
│   │   ├── algorithms.rs    Catálogo de algoritmos PQ y sus capacidades
│   │   ├── profile.rs       Extensiones X.509, reglas por algoritmo y plantillas
│   │   ├── validation.rs    Sujeto, SAN, pathlen
│   │   ├── security.rs      Argon2id, borrado de secretos, directorios temporales
│   │   ├── openssl/         Localización y ejecución del binario OpenSSL
│   │   ├── db/              Esquema SQLite, migraciones y repositorios
│   │   ├── pki/             Claves, CSR, certificados, revocación, PKCS#12
│   │   └── commands.rs      Comandos expuestos a la interfaz
│   ├── tests/               Tests de integración con OpenSSL real
│   └── tauri.conf.json      Configuración de la aplicación y del empaquetado
├── scripts/
│   ├── build-openssl.sh     Compila OpenSSL 3.5.9 estático para cada plataforma
│   └── package-release.sh   Reúne los paquetes en dist-release/
└── .github/workflows/       CI y releases
```

## Estado y limitaciones

PQ Lab está en versión **0.2.0**:

- **Plataformas.**
  - El desarrollo y los tests se han hecho en macOS (Apple Silicon).
  - Los paquetes de Windows y Linux se generan, pero aún no se han probado a fondo en
    equipos reales con esos sistemas.
  - La compilación nativa en Windows (MSVC) no se ha probado; la vía comprobada es la
    compilación cruzada desde macOS.
- **Interoperabilidad.** Los certificados se validan con OpenSSL 3.5. El soporte de
  certificados PQ en navegadores, servidores TLS y otras bibliotecas todavía es
  limitado, así que un certificado válido para OpenSSL puede no serlo para otros
  consumidores.
- **Fuera de alcance:**
  - algoritmos clásicos y certificados híbridos o *composite*;
  - respondedor OCSP;
  - tokens PKCS#11 y HSM;
  - exportación SSH;
  - uso multiusuario.
- **Idioma.** La interfaz está en español; la estructura de traducciones permite añadir
  otros idiomas.

Las contribuciones son bienvenidas mediante *issues* y *pull requests*.

## Licencia

Distribuido bajo la licencia [Apache-2.0](LICENSE).

OpenSSL se descarga en tiempo de compilación y se incluye en los paquetes bajo su propia
licencia, Apache-2.0. ML-DSA, SLH-DSA y ML-KEM son estándares del NIST (FIPS 203, 204
y 205).
