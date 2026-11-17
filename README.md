# Web Recon & Security Header Auditor

Herramienta modular de reconocimiento pasivo y auditoría de seguridad web desarrollada en Python. Permite inspeccionar aplicaciones web para evaluar su postura defensiva mediante el análisis profundo de cabeceras HTTP (OWASP), inspección de certificados SSL/TLS, auditoría de cookies (`Secure`, `HttpOnly`, `SameSite`), verificación de *Subresource Integrity* (SRI), *fingerprinting* tecnológico, extracción clasificada de endpoints y formularios, y generación de reportes ejecutivos en **JSON** y **HTML**.

---

## Características Principales

* **Inspección de Certificado SSL/TLS y Cifrado (`ssl` + `socket`):**
  * Verifica la versión del protocolo negociado (`TLSv1.3`, `TLSv1.2`), suite de cifrado (*Cipher Suite*), entidad emisora (CA) y días restantes antes de la expiración.
  * Extrae automáticamente todos los dominios y subdominios listados en la extensión **SAN (*Subject Alternative Names*)** del certificado.
* **Auditoría avanzada de cabeceras HTTP (OWASP) y puntuación (`0-100`):**
  * Verificación de cabeceras defensivas: `Content-Security-Policy`, `Strict-Transport-Security` (HSTS), `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy` (COOP) y `Cross-Origin-Resource-Policy` (CORP).
  * **Evaluación de configuración débil:** Detecta directivas riesgosas en cabeceras activas (`'unsafe-inline'`, `'unsafe-eval'`, orígenes `http://` en CSP, `max-age` corto en HSTS, políticas CORS abiertas `*`).
* **Huella Tecnológica (*Passive Stack Fingerprinting*):**
  * Identifica automáticamente CDN/WAF (Cloudflare, CloudFront, Akamai), lenguajes de backend (PHP, Laravel, ASP.NET, Django, Express, Java) y CMS/librerías (WordPress, Moodle, Drupal, Bootstrap, Swiper, jQuery, React, Vue).
* **Auditoría de Cookies (`Set-Cookie`) e Integridad de Subrecursos (`SRI` - OWASP A08):**
  * Inspección de cada cookie devuelta para verificar las banderas `Secure`, `HttpOnly` y `SameSite`.
  * Detecta scripts (`<script>`) y hojas de estilo (`<link>`) cargados desde CDNs externos que carecen del atributo criptográfico `integrity="sha..."`.
* **Reconocimiento estructurado en DOM (`HTMLParser` + Regex) y Mini-Crawler (`--crawl`):**
  * Separación limpia entre **endpoints/rutas de aplicación**, **recursos estáticos** y **enlaces externos**.
  * Auditoría pasiva de **formularios HTML (`<form>`)**, identificando métodos (`GET`/`POST`), rutas de envío y posible ausencia de tokens CSRF.
  * Opción `--crawl N` para visitar automáticamente hasta `N` subpáginas internas (priorizando rutas de login, contacto o administración) y analizar sus formularios y comentarios.
* **Escaneo de secretos, archivos JavaScript (`--scan-js`) y archivos auxiliares:**
  * Detección de Google API Keys, JWTs, AWS Access Keys, GitHub Tokens, Slack/Discord Webhooks, Stripe Keys, claves privadas y asignaciones de credenciales.
  * Revisión automática de `/robots.txt`, `/.well-known/security.txt` y `/sitemap.xml`.
* **Generador de Reporte Ejecutivo en HTML (`report_generator.py`):**
  * Exporta un dashboard visual en HTML (`--html reporte.html`) con calificación (`A` - `F`), tablas coloreadas por severidad y diseño optimizado para imprimir directamente a PDF desde el navegador (`Ctrl + P`).

---

## Estructura del Proyecto

* `web-scanner.py` — Motor principal de auditoría, análisis DOM/TLS/HTTP, mini-crawler y CLI con colores ANSI.
* `report_generator.py` — Generador de reportes ejecutivos en HTML listos para navegador o exportación PDF.

---

## Requisitos e Instalación

* Python 3.10 o superior.
* Paquete `requests` (`pip install requests`).

1. **Clona este repositorio:**
   ```bash
   git clone https://github.com/xltsignosis/web-scraper.git
   cd web-scraper
   ```

2. **Crea y activa un entorno virtual (recomendado):**
   ```powershell
   # Windows (PowerShell)
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
   ```bash
   # Linux / macOS
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Instala las dependencias necesarias:**
   ```bash
   pip install requests
   ```

---

## Uso

### 1. Escaneo estándar en terminal
```bash
python web-scanner.py -u https://ejemplo.com
```

### 2. Escaneo completo con reporte visual HTML, JSON, análisis JS y mini-crawler
```bash
python web-scanner.py -u https://ejemplo.com --scan-js --crawl 3 -o reporte.json --html reporte.html
```

### Opciones disponibles
| Parámetro | Descripción |
| :--- | :--- |
| `-u`, `--url` | URL objetivo (obligatorio, incluye `http://` o `https://`). |
| `-o`, `--output` | Ruta del archivo JSON donde exportar el reporte técnico completo. |
| `--html` | Ruta del archivo HTML donde generar el reporte visual ejecutivo (ej. `reporte.html`). |
| `--crawl N` | Visita hasta `N` subpáginas internas descubiertas (ej. `--crawl 5`). |
| `--scan-js` | Descarga y analiza archivos `.js` del mismo dominio en busca de secretos y endpoints de API. |
| `-t`, `--timeout` | Tiempo máximo de espera por petición en segundos (por defecto: `12`). |
| `--no-aux` | Omite la verificación de `/robots.txt`, `/.well-known/security.txt` y `/sitemap.xml`. |
| `--insecure` | Ignora errores de certificado SSL/TLS (útil en entornos de laboratorio con certificados autofirmados). |
| `--no-color` | Desactiva los colores ANSI en la salida de la terminal. |
| `--user-agent` | Define un `User-Agent` personalizado para las peticiones HTTP. |

---

## Aviso Legal

Esta herramienta fue diseñada con fines educativos, de aprendizaje y para auditorías de seguridad autorizadas. El uso de este script contra objetivos sin autorización previa o consentimiento explícito puede infringir normativas locales e internacionales. El autor no asume ninguna responsabilidad por el mal uso de este software.
