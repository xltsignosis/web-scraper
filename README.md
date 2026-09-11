# Web Recon & Security Header Auditor

Herramienta de reconocimiento pasivo y auditoría de seguridad web desarrollada en Python. Permite inspeccionar aplicaciones web para mapear su superficie de ataque inicial mediante el análisis de cabeceras HTTP defensivas, extracción de endpoints, detección de comentarios en código fuente y búsqueda de posibles secretos o tokens expuestos.

---

## Características

* **Auditoría de cabeceras HTTP (OWASP):**
  * Verificación de cabeceras de protección: `Content-Security-Policy`, `Strict-Transport-Security` (HSTS), `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` y `Permissions-Policy`.
  * Detección de fuga de información de infraestructura (`Server`, `X-Powered-By`).
* **Reconocimiento en código fuente:**
  * Extracción y normalización de endpoints y rutas relativas.
  * Identificación de subdominios asociados al dominio base.
  * Detección de correos electrónicos expuestos.
  * Análisis de comentarios HTML (`<!-- ... -->`) para identificar notas de desarrollo, rutas internas o código deshabilitado.
* **Escaneo pasivo de credenciales y secretos:**
  * Búsqueda mediante expresiones regulares de Google API Keys, JWTs, AWS Access Keys, claves privadas y tokens Bearer.
* **Exportación estructurada:**
  * Soporte para exportar todos los resultados en formato JSON para facilitar su integración en informes de auditoría o pipelines de análisis.

---

## Requisitos

* Python 3.9 o superior.
* Conexión a Internet para realizar las peticiones HTTP.

---

## Instalación

1. **Clona este repositorio:**
   ```bash
   git clone [https://github.com/TU_USUARIO/TU_REPOSITORIO.git](https://github.com/TU_USUARIO/TU_REPOSITORIO.git)
   cd TU_REPOSITORIO

2. **Crea y activa un entorno virtual (recomendado)**
    Windows(PowerShell)
    python -m venv .venv
    .\.venv\Scripts\Activate.ps1

    En Linux / macOS
    python3 -m venv .venv
    source .venv/bin/activate

3. **Instala las dependencias necesarias:**
    pip install requests

## Ejecuta el script proporcionando la URL objetivo con el parámetro -u o --url:
    python web-scanner.py -u https://ejemplo.com


## Escaneo con exportación a JSON Utiliza la bandera -o o --output indicando el nombre del archivo de salida:

    python web-scanner.py -u https://ejemplo.com -o reporte.json

Esta herramienta fue diseñada con fines educativos, de aprendizaje y para auditorías de seguridad autorizadas. El uso de este script contra objetivos sin autorización previa o consentimiento explícito puede infringir normativas locales e internacionales. El autor no asume ninguna responsabilidad por el mal uso de este software.