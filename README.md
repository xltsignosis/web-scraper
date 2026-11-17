# Web Recon & Security Header Auditor

Herramienta de reconocimiento pasivo y auditoría de seguridad web desarrollada en Python. Permite inspeccionar aplicaciones web para evaluar su postura defensiva mediante el análisis profundo de cabeceras HTTP (OWASP), auditoría de cookies (`Secure`, `HttpOnly`, `SameSite`), extracción clasificada de endpoints y formularios, detección de comentarios en HTML/JavaScript y búsqueda de posibles secretos o tokens expuestos.

---

## Características

* **Auditoría avanzada de cabeceras HTTP (OWASP) y puntuación de seguridad:**
  * Verificación de cabeceras defensivas: `Content-Security-Policy`, `Strict-Transport-Security` (HSTS), `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy` (COOP) y `Cross-Origin-Resource-Policy` (CORP).
  * **Evaluación de configuración débil:** Detecta directivas riesgosas en cabeceras activas (`'unsafe-inline'`, `'unsafe-eval'`, orígenes `http://` en CSP, `max-age` corto en HSTS, políticas CORS abiertas `*`).
  * Detección de fuga de información tecnológica (`Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator`, `<meta name="generator">`).
* **Auditoría de Cookies (`Set-Cookie`):**
  * Inspección de cada cookie devuelta para verificar las banderas `Secure`, `HttpOnly` y `SameSite`.
* **Reconocimiento estructurado en código fuente (`HTMLParser` + Regex):**
  * Separación limpia entre **endpoints/rutas de aplicación**, **recursos estáticos** (`.js`, `.css`, imágenes) y **enlaces externos**.
  * Identificación de subdominios en el HTML y en las cabeceras HTTP (como `Content-Security-Policy`), normalizando dominios raíz compuestos (ej. `.gob.mx`, `.com.mx`).
  * Auditoría pasiva de **formularios HTML (`<form>`)**, identificando métodos (`GET`/`POST`), rutas de envío y posible ausencia de tokens CSRF.
  * Detección de correos electrónicos filtrando falsos positivos comunes (como nombres de imágenes `@2x.png` o versiones de paquetes).
  * Extracción de comentarios HTML (`<!-- ... -->`) y comentarios de desarrollo olvidados en bloques `<script>` (`/* ... */` y `// ...`).
* **Escaneo pasivo de credenciales, secretos y archivos JavaScript (`--scan-js`):**
  * Detección de Google API Keys, JWTs, AWS Access Keys, GitHub Tokens, Slack/Discord Webhooks, Stripe Keys, claves privadas y asignaciones de secretos en código.
  * Opción `--scan-js` para analizar de forma concurrente archivos `.js` locales en busca de endpoints de API (`/api/`, `/v1/`, `/graphql`) y credenciales.
* **Comprobación de archivos auxiliares:**
  * Revisión automática de `/robots.txt` (extrayendo rutas `Disallow`) y `/.well-known/security.txt`.

---

## Requisitos

* Python 3.10 o superior.
* Paquete `requests` (`pip install requests`).

---

## Instalación

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

### Escaneo estándar
```bash
python web-scanner.py -u https://ejemplo.com
```

### Escaneo completo con análisis de archivos JavaScript y exportación a JSON
```bash
python web-scanner.py -u https://ejemplo.com --scan-js -o reporte.json
```

### Opciones disponibles
| Parámetro | Descripción |
| :--- | :--- |
| `-u`, `--url` | URL objetivo (obligatorio, incluye `http://` o `https://`). |
| `-o`, `--output` | Ruta del archivo JSON donde exportar el reporte completo. |
| `-t`, `--timeout` | Tiempo máximo de espera por petición en segundos (por defecto: `12`). |
| `--scan-js` | Descarga y analiza archivos `.js` del mismo dominio en busca de secretos y endpoints de API. |
| `--no-aux` | Omite la verificación de `/robots.txt` y `/.well-known/security.txt`. |
| `--insecure` | Ignora errores de certificado SSL/TLS (útil en entornos de prueba con certificados autofirmados). |
| `--user-agent` | Define un `User-Agent` personalizado para las peticiones HTTP. |

---

## Aviso Legal

Esta herramienta fue diseñada con fines educativos, de aprendizaje y para auditorías de seguridad autorizadas. El uso de este script contra objetivos sin autorización previa o consentimiento explícito puede infringir normativas locales e internacionales. El autor no asume ninguna responsabilidad por el mal uso de este software.
