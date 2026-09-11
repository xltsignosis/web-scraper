import argparse
import json
import re
import sys
from urllib.parse import urljoin, urlparse
import requests

EMAIL_REGEX = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
COMMENT_REGEX = r'<!--(.*?)-->'
ENDPOINT_REGEX = r'(?:href|src)=["\'](/[^"\'\s>]+)["\']'

SECRETS_PATTERNS = {
    "Google API Key": r'AIza[0-9A-Za-z-_]{35}',
    "JSON Web Token (JWT)": r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
    "AWS Access Key ID": r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
    "Slack Token": r'xox[baprs]-[0-9a-zA-Z]{10,48}',
    "Clave Privada (RSA/PGP/SSH)": r'-----BEGIN [A-Z ]+ PRIVATE KEY-----',
    "Generic Bearer Token": r'[Bb]earer\s+[A-Za-z0-9\-\._~\+\/]+=*'
}

SECURITY_HEADERS = {
    "Content-Security-Policy": "Mitiga ataques XSS y carga de recursos no autorizados.",
    "Strict-Transport-Security": "Fuerza HTTPS (HSTS) para evitar conexiones inseguras.",
    "X-Frame-Options": "Protege contra Clickjacking impidiendo iframes externos.",
    "X-Content-Type-Options": "Evita el MIME-sniffing (debe ser 'nosniff').",
    "Referrer-Policy": "Controla qué metadatos de referencia se transmiten.",
    "Permissions-Policy": "Restringe el acceso a APIs del dispositivo (cámara, micro, GPS)."
}


def build_subdomain_regex(domain: str) -> str:
    escaped_domain = re.escape(domain)
    return rf'[a-zA-Z0-9.-]+\.{escaped_domain}'


def analyze_headers(response: requests.Response) -> dict:
    headers = response.headers
    results = {
        "technologies": {
            "server": headers.get("Server", "Oculto o no configurado"),
            "x_powered_by": headers.get("X-Powered-By", "Oculto")
        },
        "present_security_headers": {},
        "missing_security_headers": {}
    }

    for sec_header, description in SECURITY_HEADERS.items():
        if sec_header in headers:
            results["present_security_headers"][sec_header] = headers[sec_header]
        else:
            results["missing_security_headers"][sec_header] = description

    return results


def find_secrets(text: str) -> dict:
    found_secrets = {}
    for name, pattern in SECRETS_PATTERNS.items():
        matches = list(set(re.findall(pattern, text)))
        if matches:
            found_secrets[name] = matches
    return found_secrets


def parse_page(html: str, target_domain: str, base_url: str) -> dict:
    subdomain_pattern = build_subdomain_regex(target_domain)

    emails = sorted(list(set(re.findall(EMAIL_REGEX, html))))
    subdomains = sorted(list(set(re.findall(subdomain_pattern, html))))
    raw_comments = re.findall(COMMENT_REGEX, html, flags=re.DOTALL)
    cleaned_comments = [c.strip() for c in raw_comments if c.strip()]
    endpoints = sorted(list(set(re.findall(ENDPOINT_REGEX, html))))
    secrets = find_secrets(html)

    return {
        "subdomains": subdomains,
        "emails": emails,
        "endpoints": [urljoin(base_url, ep) for ep in endpoints],
        "comments": cleaned_comments,
        "secrets": secrets
    }


def print_terminal_results(url: str, header_data: dict, page_data: dict):
    print("\n" + "=" * 60)
    print(" [*] AUDITORÍA DE CABECERAS HTTP")
    print("=" * 60)

    tech = header_data["technologies"]
    print(f"\n[+] Tecnologías expuestas:\n  Server: {tech['server']}\n  X-Powered-By: {tech['x_powered_by']}")

    print("\n[+] Cabeceras de seguridad activas:")
    for h, val in header_data["present_security_headers"].items():
        print(f"  [OK] {h}: {val[:65]}...")

    if header_data["missing_security_headers"]:
        print("\n[-] Cabeceras ausentes:")
        for h, desc in header_data["missing_security_headers"].items():
            print(f"  [MISSING] {h} -> {desc}")

    print("\n" + "=" * 60)
    print(f" [*] ANÁLISIS DE CÓDIGO FUENTE: {url}")
    print("=" * 60)

    print(f"\n[!] Subdominios ({len(page_data['subdomains'])}):")
    for s in page_data["subdomains"]:
        print(f"  - {s}")

    print(f"\n[!] Correos electrónicos ({len(page_data['emails'])}):")
    for m in page_data["emails"]:
        print(f"  - {m}")

    print(f"\n[!] Posibles Secretos / Tokens expuestos ({len(page_data['secrets'])} categorías):")
    if page_data["secrets"]:
        for sec_type, hits in page_data["secrets"].items():
            print(f"  [ALERTA] {sec_type}:")
            for item in hits:
                masked = item if len(item) < 15 else item[:6] + "..." + item[-4:]
                print(f"    * {masked}")
    else:
        print("  - No se detectaron patrones conocidos de claves o tokens.")

    print(f"\n[!] Endpoints / Rutas relativas ({len(page_data['endpoints'])}):")
    for ep in page_data["endpoints"]:
        print(f"  - {ep}")

    print(f"\n[!] Comentarios HTML ({len(page_data['comments'])}):")
    for idx, c in enumerate(page_data["comments"], 1):
        preview = c if len(c) < 140 else c[:137] + "..."
        print(f"  [{idx}] {preview}")


def main():
    parser = argparse.ArgumentParser(
        description="Auditor web: Reconocimiento pasivo, cabeceras, detección de secretos y exportación JSON."
    )
    parser.add_argument("-u", "--url", required=True, help="URL objetivo (ej. https://ejemplo.com)")
    parser.add_argument("-o", "--output", help="Ruta de archivo JSON donde guardar el informe.")
    args = parser.parse_args()

    parsed_url = urlparse(args.url)
    if not parsed_url.scheme or not parsed_url.netloc:
        print("[-] Formato de URL inválido. Incluye http:// o https://", file=sys.stderr)
        sys.exit(1)

    domain = parsed_url.netloc.split(":")[0]

    try:
        response = requests.get(
            args.url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
            timeout=10
        )
    except requests.exceptions.RequestException as error:
        print(f"[-] Error al conectar con {args.url}: {error}", file=sys.stderr)
        sys.exit(1)

    headers_result = analyze_headers(response)
    page_result = parse_page(response.text, domain, args.url)

    print_terminal_results(args.url, headers_result, page_result)

    if args.output:
        full_report = {
            "target_url": args.url,
            "domain": domain,
            "status_code": response.status_code,
            "headers_analysis": headers_result,
            "recon_data": page_result
        }
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(full_report, f, indent=4, ensure_ascii=False)
            print(f"\n[+] Informe guardado con éxito en: {args.output}")
        except OSError as e:
            print(f"[-] Error al guardar el archivo JSON: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()