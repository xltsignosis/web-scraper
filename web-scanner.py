import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from html.parser import HTMLParser
import json
import os
import re
import socket
import ssl
import sys
from typing import Any
from urllib.parse import urljoin, urlparse
import urllib3
import requests

from report_generator import generate_html_report


class Colors:
    """Códigos ANSI para colorear la salida en terminal (Windows, Linux, macOS)."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    MAGENTA = "\033[95m"
    GRAY = "\033[90m"

    @classmethod
    def disable(cls):
        cls.RESET = ""
        cls.BOLD = ""
        cls.CYAN = ""
        cls.GREEN = ""
        cls.YELLOW = ""
        cls.RED = ""
        cls.MAGENTA = ""
        cls.GRAY = ""


def enable_windows_ansi():
    if os.name == "nt":
        os.system("")


EMAIL_REGEX = re.compile(
    r'\b[a-zA-Z0-9._%+-]+@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,15}\b'
)
FALSE_POSITIVE_EMAIL_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp",
    ".css", ".js", ".mjs", ".map", ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".webm", ".mp3", ".wav", ".pdf", ".zip"
}

HTML_COMMENT_REGEX = re.compile(r'<!--(.*?)-->', re.DOTALL)
JS_MULTI_COMMENT_REGEX = re.compile(r'/\*(.*?)\*/', re.DOTALL)
JS_SINGLE_COMMENT_REGEX = re.compile(r'(?<![:\'"a-zA-Z0-9])//([^\n\r]+)')
SCRIPT_TAG_CONTENT_REGEX = re.compile(
    r'<script\b[^>]*>(.*?)</script>', re.DOTALL | re.IGNORECASE
)

JS_API_ENDPOINT_REGEX = re.compile(
    r'["\']((?:/api/|/v[0-9]+/|/graphql|/rest/|/auth/|/admin/|/wp-json/)[^"\'\s<>]{1,150})["\']',
    re.IGNORECASE
)
GENERIC_REL_PATH_REGEX = re.compile(
    r'(?:href|src|action|data-url|data-src)=["\'](/[^"\'\s<>]+)["\']',
    re.IGNORECASE
)

STATIC_EXTENSIONS = {
    ".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif",
    ".svg", ".ico", ".webp", ".avif", ".woff", ".woff2", ".ttf",
    ".eot", ".otf", ".mp4", ".webm", ".mp3", ".pdf", ".zip", ".gz"
}

SECRETS_PATTERNS = {
    "Google API Key": re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b'),
    "JSON Web Token (JWT)": re.compile(
        r'\beyJ[A-Za-z0-9\-_=]{10,}\.eyJ[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_.+/=]{10,}\b'
    ),
    "AWS Access Key ID": re.compile(
        r'\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b'
    ),
    "GitHub Token": re.compile(r'\bgh[pousr]_[A-Za-z0-9_]{36,255}\b'),
    "Slack Token": re.compile(r'\bxox[baprs]-[0-9a-zA-Z\-]{10,72}\b'),
    "Slack / Discord Webhook": re.compile(
        r'https://(?:hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+|(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+)'
    ),
    "Stripe API Key": re.compile(r'\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99}\b'),
    "Clave Privada (RSA/PGP/SSH/EC)": re.compile(
        r'-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----'
    ),
    "Generic Bearer Token": re.compile(
        r'\b[Bb]earer\s+[A-Za-z0-9\-._~+/]{24,}=*\b'
    ),
    "Asignación de Secreto / API Key": re.compile(
        r'(?i)\b(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b\s*[:=]\s*["\'][A-Za-z0-9\-._~+/]{16,128}["\']'
    ),
}

SECURITY_HEADERS = {
    "Content-Security-Policy": "Mitiga ataques XSS e inyección de recursos no autorizados.",
    "Strict-Transport-Security": "Fuerza conexiones HTTPS (HSTS) evitando ataques de downgrade.",
    "X-Frame-Options": "Protege contra Clickjacking impidiendo embeber la página en iframes.",
    "X-Content-Type-Options": "Evita el MIME-sniffing (debe configurarse como 'nosniff').",
    "Referrer-Policy": "Controla qué información de referencia se envía en peticiones salientes.",
    "Permissions-Policy": "Restringe el acceso del navegador a APIs sensibles (cámara, micro, GPS).",
    "Cross-Origin-Opener-Policy": "Aísla el contexto de navegación frente a ataques cross-origin (COOP).",
    "Cross-Origin-Resource-Policy": "Controla qué orígenes pueden cargar los recursos de la página (CORP)."
}

TECH_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Varnish",
    "Via",
    "CF-Ray",
    "X-Amz-Cf-Id"
]

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


def extract_root_domain(hostname: str) -> str:
    """Extrae el dominio raíz (ej. sub.ejemplo.gob.mx -> ejemplo.gob.mx)."""
    hostname = hostname.lower().strip(".")
    if hostname.startswith("www."):
        hostname = hostname[4:]

    parts = hostname.split(".")
    if len(parts) <= 2:
        return hostname

    multi_part_tlds = {
        "gob.mx", "com.mx", "org.mx", "edu.mx", "net.mx",
        "co.uk", "org.uk", "ac.uk", "com.ar", "com.co",
        "com.es", "gob.es", "com.br", "com.pe", "com.cl"
    }
    last_two = ".".join(parts[-2:])
    if last_two in multi_part_tlds and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def build_subdomain_regex(domain: str) -> re.Pattern:
    root_domain = extract_root_domain(domain)
    escaped_domain = re.escape(root_domain)
    return re.compile(
        rf'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.)+{escaped_domain}\b',
        re.IGNORECASE
    )


class PageHTMLAnalyzer(HTMLParser):
    """Analizador DOM ligero basado en la librería estándar para extraer enlaces, scripts, SRI, formularios y metadatos."""

    def __init__(self, base_url: str, root_domain: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.root_domain = root_domain
        self.links: set[str] = set()
        self.scripts: set[str] = set()
        self.stylesheets: set[str] = set()
        self.forms: list[dict[str, Any]] = []
        self.meta_generators: list[str] = []
        self.missing_sri: list[dict[str, str]] = []
        self._seen_sri_urls: set[str] = set()
        self._current_form: dict[str, Any] | None = None

    def _is_external_domain(self, full_url: str) -> bool:
        parsed = urlparse(full_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return False
        host = parsed.netloc.split(":")[0].lower()
        return host != self.root_domain and not host.endswith("." + self.root_domain)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        attr_dict = {k.lower(): (v or "") for k, v in attrs if k}
        tag = tag.lower()

        if tag in ("a", "area") and attr_dict.get("href"):
            self.links.add(attr_dict["href"].strip())
        elif tag == "script" and attr_dict.get("src"):
            src = attr_dict["src"].strip()
            self.scripts.add(src)
            full_src = urljoin(self.base_url, src)
            if self._is_external_domain(full_src) and not attr_dict.get("integrity"):
                if full_src not in self._seen_sri_urls:
                    self._seen_sri_urls.add(full_src)
                    self.missing_sri.append({"tag": "script", "url": full_src})
        elif tag == "link":
            rel = attr_dict.get("rel", "").lower()
            href = attr_dict.get("href", "").strip()
            if href:
                if "stylesheet" in rel:
                    self.stylesheets.add(href)
                    full_href = urljoin(self.base_url, href)
                    if self._is_external_domain(full_href) and not attr_dict.get("integrity"):
                        if full_href not in self._seen_sri_urls:
                            self._seen_sri_urls.add(full_href)
                            self.missing_sri.append({"tag": "link[stylesheet]", "url": full_href})
                else:
                    self.links.add(href)
        elif tag in ("img", "iframe", "embed", "source") and attr_dict.get("src"):
            self.links.add(attr_dict["src"].strip())
        elif tag == "meta":
            name = attr_dict.get("name", "").lower()
            content = attr_dict.get("content", "").strip()
            if name == "generator" and content:
                self.meta_generators.append(content)
        elif tag == "form":
            action = attr_dict.get("action", "").strip()
            method = attr_dict.get("method", "GET").upper()
            self._current_form = {
                "action": urljoin(self.base_url, action) if action else self.base_url,
                "method": method,
                "inputs": [],
                "has_csrf_token": False
            }
        elif tag in ("input", "textarea", "select") and self._current_form is not None:
            input_name = attr_dict.get("name", "")
            input_type = attr_dict.get("type", "text" if tag == "input" else tag).lower()
            self._current_form["inputs"].append({
                "name": input_name,
                "type": input_type
            })
            if any(tok in input_name.lower() for tok in ("csrf", "xsrf", "token", "__requestverificationtoken", "authenticity_token")):
                self._current_form["has_csrf_token"] = True

    def handle_endtag(self, tag: str):
        if tag.lower() == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


def inspect_tls_certificate(hostname: str, port: int = 443, timeout: int = 8) -> dict[str, Any]:
    """Inspecciona el certificado SSL/TLS, suite de cifrado, vigencia y nombres alternativos (SAN)."""
    tls_report: dict[str, Any] = {
        "enabled": False,
        "protocol_version": None,
        "cipher_suite": None,
        "cipher_bits": None,
        "subject": None,
        "issuer": None,
        "not_before": None,
        "not_after": None,
        "days_remaining": None,
        "san_domains": [],
        "warnings": []
    }
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_report["enabled"] = True
                tls_report["protocol_version"] = ssock.version()
                cipher = ssock.cipher()
                if cipher:
                    tls_report["cipher_suite"] = cipher[0]
                    tls_report["cipher_bits"] = cipher[2]

                cert = ssock.getpeercert()
                if cert:
                    subj = dict(x[0] for x in cert.get("subject", ()))
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    tls_report["subject"] = subj.get("commonName", hostname)
                    tls_report["issuer"] = (
                        f"{issuer.get('organizationName', 'Desconocido')} "
                        f"({issuer.get('commonName', '')})"
                    ).strip()
                    tls_report["not_before"] = cert.get("notBefore")
                    tls_report["not_after"] = cert.get("notAfter")

                    if cert.get("notAfter"):
                        try:
                            exp_dt = datetime.strptime(
                                cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                            ).replace(tzinfo=timezone.utc)
                            days_left = (exp_dt - datetime.now(timezone.utc)).days
                            tls_report["days_remaining"] = days_left
                            if days_left < 0:
                                tls_report["warnings"].append("El certificado SSL/TLS ha EXPIRADO.")
                            elif days_left < 20:
                                tls_report["warnings"].append(
                                    f"El certificado SSL/TLS está próximo a expirar ({days_left} días restantes)."
                                )
                        except ValueError:
                            pass

                    san = [
                        val.lower()
                        for key, val in cert.get("subjectAltName", ())
                        if key == "DNS"
                    ]
                    tls_report["san_domains"] = sorted(set(san))

                if tls_report["protocol_version"] in ("TLSv1", "TLSv1.1", "SSLv3"):
                    tls_report["warnings"].append(
                        f"Protocolo TLS obsoleto e inseguro negociado: {tls_report['protocol_version']}."
                    )
    except Exception as exc:
        tls_report["error"] = str(exc)

    return tls_report


def fingerprint_technologies(
    headers: dict[str, str],
    cookies: list[dict[str, Any]],
    html: str,
    url: str,
    meta_generators: list[str]
) -> list[str]:
    """Identifica de forma pasiva el stack tecnológico (WAF, Backend, CMS y librerías JS/CSS)."""
    detected: set[str] = set()
    lower_headers = {k.lower(): v.lower() for k, v in headers.items()}
    cookie_names = {c["name"].lower() for c in cookies}
    html_lower = html.lower()

    # CDN / WAF
    if "cf-ray" in lower_headers or "cloudflare" in lower_headers.get("server", "") or "__cf_bm" in cookie_names:
        detected.add("Cloudflare (CDN/WAF)")
    if "x-amz-cf-id" in lower_headers:
        detected.add("AWS CloudFront")
    if "x-akamai-transformed" in lower_headers or "akamai" in lower_headers.get("server", ""):
        detected.add("Akamai CDN")

    # Servidor Web
    srv = headers.get("Server", "")
    if srv and srv.lower() not in ("cloudflare", "oculto o no configurado"):
        detected.add(f"Server: {srv}")

    # Lenguajes / Frameworks Backend
    if "phpsessid" in cookie_names or ".php" in url.lower() or "php" in lower_headers.get("x-powered-by", ""):
        detected.add("PHP")
    if "laravel_session" in cookie_names or "xsrf-token" in cookie_names:
        detected.add("Laravel")
    if "asp.net_sessionid" in cookie_names or "__viewstate" in html_lower or "x-aspnet-version" in lower_headers:
        detected.add("ASP.NET")
    if "csrftoken" in cookie_names or "sessionid" in cookie_names and "django" in html_lower:
        detected.add("Django (Python)")
    if "connect.sid" in cookie_names or "express" in lower_headers.get("x-powered-by", ""):
        detected.add("Express / Node.js")
    if "jsessionid" in cookie_names:
        detected.add("Java (Servlet/Spring)")

    # CMS y Plataformas
    if "/wp-content/" in html_lower or "/wp-includes/" in html_lower:
        detected.add("WordPress")
    if "drupal" in html_lower or "x-drupal-cache" in lower_headers:
        detected.add("Drupal")
    if "/mod/page/view.php" in html_lower or "moodle" in html_lower:
        detected.add("Moodle LMS (Integración/Enlaces)")

    # Librerías Frontend
    if "bootstrap" in html_lower:
        detected.add("Bootstrap CSS/JS")
    if "swiper" in html_lower:
        detected.add("Swiper.js")
    if "jquery" in html_lower:
        detected.add("jQuery")
    if "_next/static" in html_lower:
        detected.add("Next.js (React)")
    elif "react" in html_lower and "react-dom" in html_lower:
        detected.add("React")
    if "vue.js" in html_lower or "vue.min.js" in html_lower:
        detected.add("Vue.js")

    for gen in meta_generators:
        detected.add(f"Generator: {gen}")

    return sorted(detected)


def evaluate_security_header_warnings(headers: dict[str, str]) -> list[str]:
    """Evalúa la calidad de las cabeceras de seguridad presentes y detecta configuraciones débiles."""
    warnings: list[str] = []
    lower_headers = {k.lower(): v for k, v in headers.items()}

    csp = lower_headers.get("content-security-policy", "")
    if csp:
        if "'unsafe-inline'" in csp:
            warnings.append("CSP permite 'unsafe-inline' (reduce la protección contra XSS).")
        if "'unsafe-eval'" in csp:
            warnings.append("CSP permite 'unsafe-eval' (permite ejecución dinámica de código JS).")
        if re.search(r'(?:^|\s|;)http://', csp):
            warnings.append("CSP permite cargar recursos mediante HTTP sin cifrar (http://).")
        if re.search(r'(?:default-src|script-src)\s+[^;]*(?:^|\s)\*(?:\s|;|$)', csp):
            warnings.append("CSP utiliza comodín global '*' en directivas críticas (default-src / script-src).")

    hsts = lower_headers.get("strict-transport-security", "")
    if hsts:
        match = re.search(r'max-age\s*=\s*(\d+)', hsts, re.IGNORECASE)
        if not match:
            warnings.append("HSTS no especifica la directiva 'max-age'.")
        else:
            max_age = int(match.group(1))
            if max_age < 31536000:
                warnings.append(f"HSTS tiene un max-age menor a 1 año ({max_age}s < 31536000s).")
        if "includesubdomains" not in hsts.lower():
            warnings.append("HSTS no incluye la directiva 'includeSubDomains'.")

    xcto = lower_headers.get("x-content-type-options", "")
    if xcto and xcto.strip().lower() != "nosniff":
        warnings.append(f"X-Content-Type-Options tiene un valor inesperado: '{xcto}' (debe ser 'nosniff').")

    xfo = lower_headers.get("x-frame-options", "")
    if xfo and xfo.strip().upper() not in ("DENY", "SAMEORIGIN"):
        warnings.append(f"X-Frame-Options usa un valor obsoleto o no estándar: '{xfo}'.")

    ref = lower_headers.get("referrer-policy", "")
    if ref and any(weak in ref.lower() for weak in ("unsafe-url", "no-referrer-when-downgrade")):
        warnings.append(f"Referrer-Policy usa una política permisiva ('{ref}') que puede filtrar URLs completas.")

    acao = lower_headers.get("access-control-allow-origin", "")
    acac = lower_headers.get("access-control-allow-credentials", "")
    if acao.strip() == "*":
        if acac.strip().lower() == "true":
            warnings.append("CORS crítico: Access-Control-Allow-Origin: '*' combinado con Allow-Credentials: true.")
        else:
            warnings.append("CORS abierto: Access-Control-Allow-Origin permite cualquier origen ('*').")

    return warnings


def analyze_cookies(response: requests.Response) -> list[dict[str, Any]]:
    """Analiza las cookies devueltas en busca de banderas de seguridad ausentes (Secure, HttpOnly, SameSite)."""
    cookies_report: list[dict[str, Any]] = []
    raw_headers = getattr(response.raw, "headers", None)

    set_cookie_headers: list[str] = []
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        set_cookie_headers = raw_headers.getlist("Set-Cookie")
    elif raw_headers is not None and hasattr(raw_headers, "get_all"):
        set_cookie_headers = raw_headers.get_all("Set-Cookie") or []
    elif "Set-Cookie" in response.headers:
        set_cookie_headers = [response.headers["Set-Cookie"]]

    for raw_cookie in set_cookie_headers:
        parts = [p.strip() for p in raw_cookie.split(";") if p.strip()]
        if not parts:
            continue
        name_val = parts[0].split("=", 1)
        cookie_name = name_val[0].strip()
        attrs_lower = [p.lower() for p in parts[1:]]

        has_secure = any(a == "secure" for a in attrs_lower)
        has_httponly = any(a == "httponly" for a in attrs_lower)
        samesite_val = None
        for a in attrs_lower:
            if a.startswith("samesite="):
                samesite_val = a.split("=", 1)[1].strip()

        issues: list[str] = []
        if not has_secure:
            issues.append("Falta 'Secure' (puede transmitirse por HTTP plano)")
        if not has_httponly:
            issues.append("Falta 'HttpOnly' (accesible vía JavaScript / document.cookie)")
        if not samesite_val:
            issues.append("Falta 'SameSite' (riesgo potencial de CSRF)")
        elif samesite_val == "none" and not has_secure:
            issues.append("SameSite=None sin bandera 'Secure'")

        cookies_report.append({
            "name": cookie_name,
            "secure": has_secure,
            "httponly": has_httponly,
            "samesite": samesite_val or "Ausente",
            "issues": issues
        })

    return cookies_report


def analyze_headers(
    response: requests.Response,
    meta_generators: list[str] | None = None
) -> dict[str, Any]:
    headers = response.headers
    exposed_tech: dict[str, str] = {}
    for tech_header in TECH_HEADERS:
        if tech_header in headers:
            exposed_tech[tech_header] = headers[tech_header]

    present_security: dict[str, str] = {}
    missing_security: dict[str, str] = {}

    for sec_header, description in SECURITY_HEADERS.items():
        if sec_header in headers:
            present_security[sec_header] = headers[sec_header]
        else:
            missing_security[sec_header] = description

    warnings = evaluate_security_header_warnings(dict(headers))
    cookies = analyze_cookies(response)
    detected_stack = fingerprint_technologies(
        dict(headers), cookies, response.text, response.url, meta_generators or []
    )

    core_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    ]
    present_core = sum(1 for h in core_headers if h in present_security)
    base_score = int((present_core / len(core_headers)) * 100)
    penalty = min(30, len(warnings) * 5 + sum(len(c["issues"]) for c in cookies) * 3)
    security_score = max(0, base_score - penalty)

    return {
        "security_score": security_score,
        "detected_stack": detected_stack,
        "technologies": {
            "server": headers.get("Server", "Oculto o no configurado"),
            "x_powered_by": headers.get("X-Powered-By", "Oculto"),
            "all_exposed_headers": exposed_tech
        },
        "present_security_headers": present_security,
        "missing_security_headers": missing_security,
        "header_warnings": warnings,
        "cookies_analysis": cookies
    }


def find_secrets(text: str) -> dict[str, list[str]]:
    found_secrets: dict[str, list[str]] = {}
    for name, pattern in SECRETS_PATTERNS.items():
        matches = sorted(set(pattern.findall(text)))
        if matches:
            found_secrets[name] = matches
    return found_secrets


def filter_valid_emails(raw_emails: list[str]) -> list[str]:
    valid: set[str] = set()
    for email in raw_emails:
        lower = email.lower().strip(".")
        if any(lower.endswith(ext) for ext in FALSE_POSITIVE_EMAIL_EXTENSIONS):
            continue
        domain_part = lower.split("@", 1)[-1]
        if all(part.isdigit() for part in domain_part.split(".")):
            continue
        valid.add(email)
    return sorted(valid)


def extract_comments(html: str) -> list[str]:
    """Extrae comentarios HTML y comentarios olvidados en bloques <script> inline."""
    comments: list[str] = []
    seen: set[str] = set()

    for raw in HTML_COMMENT_REGEX.findall(html):
        cleaned = raw.strip()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            comments.append(cleaned)

    interesting_keywords = (
        "todo", "fixme", "hack", "bug", "nota", "note", "password",
        "secret", "token", "key", "admin", "debug", "api", "deprecated", "cve"
    )
    for script_body in SCRIPT_TAG_CONTENT_REGEX.findall(html):
        for multi in JS_MULTI_COMMENT_REGEX.findall(script_body):
            cleaned = multi.strip()
            if cleaned and len(cleaned) > 4 and cleaned not in seen:
                if any(k in cleaned.lower() for k in interesting_keywords) or len(cleaned) < 300:
                    seen.add(cleaned)
                    comments.append(f"[JS /* */] {cleaned}")

        for single in JS_SINGLE_COMMENT_REGEX.findall(script_body):
            cleaned = single.strip()
            if cleaned and len(cleaned) > 4 and not cleaned.startswith("//") and cleaned not in seen:
                if any(k in cleaned.lower() for k in interesting_keywords):
                    seen.add(cleaned)
                    comments.append(f"[JS //] {cleaned}")

    return comments


def classify_urls(
    raw_urls: set[str],
    base_url: str,
    root_domain: str
) -> tuple[list[str], list[str], list[str]]:
    """Clasifica las URLs encontradas en: endpoints internos, recursos estáticos y enlaces externos."""
    endpoints: set[str] = set()
    static_assets: set[str] = set()
    external_links: set[str] = set()

    ignored_schemes = ("javascript:", "mailto:", "tel:", "data:", "blob:", "#")

    for raw in raw_urls:
        cleaned = raw.strip()
        if not cleaned or cleaned.lower().startswith(ignored_schemes):
            continue
        if "${" in cleaned or "{{" in cleaned:
            continue

        full_url = urljoin(base_url, cleaned)
        parsed = urlparse(full_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            continue

        host = parsed.netloc.split(":")[0].lower()
        path_lower = parsed.path.lower()
        is_static = any(path_lower.endswith(ext) for ext in STATIC_EXTENSIONS)

        if host == root_domain or host.endswith("." + root_domain):
            if is_static:
                static_assets.add(full_url)
            else:
                endpoints.add(full_url)
        else:
            external_links.add(full_url)

    return sorted(endpoints), sorted(static_assets), sorted(external_links)


def parse_page(
    html: str,
    target_domain: str,
    base_url: str,
    response_headers: dict[str, str] | None = None,
    san_domains: list[str] | None = None
) -> dict[str, Any]:
    root_domain = extract_root_domain(target_domain)
    subdomain_pattern = build_subdomain_regex(root_domain)

    headers_text = ""
    if response_headers:
        headers_text = "\n".join(f"{k}: {v}" for k, v in response_headers.items())
    san_text = "\n".join(san_domains or [])
    combined_search_text = f"{html}\n{headers_text}\n{san_text}"

    subdomains = sorted({
        s.lower() for s in subdomain_pattern.findall(combined_search_text)
    })

    raw_emails = EMAIL_REGEX.findall(html)
    emails = filter_valid_emails(raw_emails)

    comments = extract_comments(html)

    dom_analyzer = PageHTMLAnalyzer(base_url, root_domain)
    try:
        dom_analyzer.feed(html)
    except Exception:
        pass

    candidate_urls: set[str] = set()
    candidate_urls.update(dom_analyzer.links)
    candidate_urls.update(dom_analyzer.scripts)
    candidate_urls.update(dom_analyzer.stylesheets)
    candidate_urls.update(GENERIC_REL_PATH_REGEX.findall(html))
    candidate_urls.update(JS_API_ENDPOINT_REGEX.findall(html))

    endpoints, static_assets, external_links = classify_urls(
        candidate_urls, base_url, root_domain
    )

    secrets = find_secrets(html)

    forms_summary = []
    for form in dom_analyzer.forms:
        form_warnings = []
        input_names_lower = {i["name"].lower() for i in form["inputs"] if i["name"]}
        input_types_lower = {i["type"].lower() for i in form["inputs"]}
        if form["method"] == "POST" and not form["has_csrf_token"]:
            form_warnings.append("Formulario POST sin campo CSRF aparente")
        if form["method"] == "GET":
            if "password" in input_types_lower or any(
                k in name for name in input_names_lower for k in ("pass", "pwd", "email", "correo", "mensaje", "telefono", "tel")
            ) or form["action"].lower().endswith((".php", ".asp", ".aspx", ".jsp")):
                form_warnings.append("Formulario envía datos a script/contacto mediante GET (expone parámetros en URL y logs)")
        if form["action"].startswith("http://"):
            form_warnings.append("El formulario envía datos por HTTP sin cifrar")
        forms_summary.append({
            **form,
            "warnings": form_warnings
        })

    return {
        "root_domain": root_domain,
        "subdomains": subdomains,
        "emails": emails,
        "endpoints": endpoints,
        "static_assets": static_assets,
        "external_links": external_links,
        "forms": forms_summary,
        "missing_sri": dom_analyzer.missing_sri,
        "meta_generators": dom_analyzer.meta_generators,
        "comments": comments,
        "secrets": secrets
    }


def scan_javascript_files(
    session: requests.Session,
    static_assets: list[str],
    timeout: int,
    verify_ssl: bool,
    max_files: int = 10
) -> dict[str, Any]:
    """Descarga y analiza archivos .js del mismo dominio en busca de secretos y endpoints de API."""
    js_urls = [
        u for u in static_assets
        if urlparse(u).path.lower().endswith(".js")
        and not any(lib in u.lower() for lib in (
            "bootstrap.bundle.min.js", "bootstrap.min.js", "jquery.min.js",
            "swiper-bundle.min.js", "popper.min.js"
        ))
    ][:max_files]

    js_secrets: dict[str, list[str]] = {}
    js_api_endpoints: set[str] = set()
    scanned_files: list[str] = []

    if not js_urls:
        return {"scanned_files": [], "secrets": {}, "api_endpoints": []}

    def fetch_js(url: str) -> tuple[str, str]:
        try:
            resp = session.get(url, timeout=timeout, verify=verify_ssl)
            if resp.status_code == 200 and len(resp.text) < 2_000_000:
                return url, resp.text
        except requests.RequestException:
            pass
        return url, ""

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(fetch_js, url) for url in js_urls]
        for future in as_completed(futures):
            url, content = future.result()
            if not content:
                continue
            scanned_files.append(url)
            found = find_secrets(content)
            for sec_type, items in found.items():
                existing = set(js_secrets.get(sec_type, []))
                existing.update(items)
                js_secrets[sec_type] = sorted(existing)

            for api_ep in JS_API_ENDPOINT_REGEX.findall(content):
                js_api_endpoints.add(urljoin(url, api_ep))

    return {
        "scanned_files": sorted(scanned_files),
        "secrets": js_secrets,
        "api_endpoints": sorted(js_api_endpoints)
    }


def crawl_subpages(
    session: requests.Session,
    endpoints: list[str],
    initial_url: str,
    root_domain: str,
    max_pages: int,
    timeout: int,
    verify_ssl: bool
) -> dict[str, Any]:
    """Rastrea de forma controlada hasta N subpáginas internas para descubrir formularios, correos o secretos."""
    priority_keywords = ("login", "signin", "auth", "admin", "contacto", "contact", "registro", "register", "user")
    candidates = [u for u in endpoints if u.rstrip("/") != initial_url.rstrip("/")]
    candidates.sort(key=lambda u: (0 if any(k in u.lower() for k in priority_keywords) else 1, len(u)))
    targets = candidates[:max_pages]

    pages_crawled: list[dict[str, Any]] = []
    extra_forms: list[dict[str, Any]] = []
    extra_emails: set[str] = set()
    extra_secrets: dict[str, list[str]] = {}

    for url in targets:
        try:
            resp = session.get(url, timeout=timeout, verify=verify_ssl)
            if "text/html" not in resp.headers.get("Content-Type", "").lower():
                continue
            sub_data = parse_page(resp.text, root_domain, resp.url)
            pages_crawled.append({
                "url": resp.url,
                "status_code": resp.status_code,
                "forms_count": len(sub_data["forms"]),
                "comments_count": len(sub_data["comments"]),
                "secrets_count": len(sub_data["secrets"])
            })
            extra_forms.extend(sub_data["forms"])
            extra_emails.update(sub_data["emails"])
            for s_type, hits in sub_data["secrets"].items():
                curr = set(extra_secrets.get(s_type, []))
                curr.update(hits)
                extra_secrets[s_type] = sorted(curr)
        except requests.RequestException:
            continue

    return {
        "pages_crawled": pages_crawled,
        "discovered_forms": extra_forms,
        "discovered_emails": sorted(extra_emails),
        "discovered_secrets": extra_secrets
    }


def check_auxiliary_files(
    session: requests.Session,
    base_url: str,
    timeout: int,
    verify_ssl: bool
) -> dict[str, Any]:
    """Comprueba de forma pasiva la existencia de robots.txt, security.txt y sitemap.xml."""
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    aux_results: dict[str, Any] = {
        "robots_txt": {"present": False, "url": f"{origin}/robots.txt", "disallowed_paths": []},
        "security_txt": {"present": False, "url": f"{origin}/.well-known/security.txt"},
        "sitemap_xml": {"present": False, "url": f"{origin}/sitemap.xml", "urls_count": 0}
    }

    try:
        r_resp = session.get(aux_results["robots_txt"]["url"], timeout=timeout, verify=verify_ssl)
        if r_resp.status_code == 200 and "user-agent" in r_resp.text.lower():
            aux_results["robots_txt"]["present"] = True
            disallowed = re.findall(r'(?i)^disallow:\s*(.+)$', r_resp.text, re.MULTILINE)
            aux_results["robots_txt"]["disallowed_paths"] = sorted({
                d.strip() for d in disallowed if d.strip()
            })[:25]
    except requests.RequestException:
        pass

    try:
        s_resp = session.get(aux_results["security_txt"]["url"], timeout=timeout, verify=verify_ssl)
        if s_resp.status_code == 200 and "contact:" in s_resp.text.lower():
            aux_results["security_txt"]["present"] = True
    except requests.RequestException:
        pass

    try:
        sm_resp = session.get(aux_results["sitemap_xml"]["url"], timeout=timeout, verify=verify_ssl)
        if sm_resp.status_code == 200 and "<urlset" in sm_resp.text.lower() or "<sitemapindex" in sm_resp.text.lower():
            aux_results["sitemap_xml"]["present"] = True
            locs = re.findall(r'<loc>(.*?)</loc>', sm_resp.text, re.IGNORECASE)
            aux_results["sitemap_xml"]["urls_count"] = len(locs)
    except requests.RequestException:
        pass

    return aux_results


def print_terminal_results(
    url: str,
    status_code: int,
    redirect_chain: list[str],
    header_data: dict[str, Any],
    page_data: dict[str, Any],
    tls_data: dict[str, Any] | None = None,
    aux_data: dict[str, Any] | None = None,
    js_data: dict[str, Any] | None = None,
    crawl_data: dict[str, Any] | None = None
):
    C = Colors
    score = header_data["security_score"]
    score_color = C.GREEN if score >= 80 else (C.YELLOW if score >= 55 else C.RED)

    print(f"\n{C.CYAN}{'=' * 70}{C.RESET}")
    print(f"{C.BOLD} [*] AUDITORÍA DE SEGURIDAD WEB Y RECONOCIMIENTO PASIVO{C.RESET}")
    print(f"{C.CYAN}{'=' * 70}{C.RESET}")
    print(f"  Objetivo       : {C.BOLD}{url}{C.RESET}")
    print(f"  Estado HTTP    : {status_code}")
    print(f"  Dominio Raíz   : {page_data['root_domain']}")
    print(f"  Puntuación Sec : {score_color}{C.BOLD}{score}/100{C.RESET}")
    if header_data.get("detected_stack"):
        print(f"  Stack Detectado: {C.MAGENTA}{', '.join(header_data['detected_stack'])}{C.RESET}")
    if redirect_chain:
        print(f"  Redirecciones  : {' -> '.join(redirect_chain)}")

    if tls_data and tls_data.get("enabled"):
        print(f"\n{C.CYAN}{'=' * 70}{C.RESET}")
        print(f"{C.BOLD} [*] 1. CERTIFICADO SSL/TLS Y CIFRADO{C.RESET}")
        print(f"{C.CYAN}{'=' * 70}{C.RESET}")
        print(f"  - Protocolo    : {C.GREEN}{tls_data['protocol_version']}{C.RESET}")
        print(f"  - Cipher Suite : {tls_data['cipher_suite']} ({tls_data['cipher_bits']} bits)")
        print(f"  - Emisor (CA)  : {tls_data['issuer']}")
        print(f"  - Vigencia     : Hasta {tls_data['not_after']} ({tls_data['days_remaining']} días restantes)")
        print(f"  - Dominios SAN : {', '.join(tls_data['san_domains'][:8])}")
        for w in tls_data.get("warnings", []):
            print(f"  {C.YELLOW}[WARN] {w}{C.RESET}")

    print(f"\n{C.CYAN}{'=' * 70}{C.RESET}")
    print(f"{C.BOLD} [*] 2. AUDITORÍA DE CABECERAS HTTP Y COOKIES{C.RESET}")
    print(f"{C.CYAN}{'=' * 70}{C.RESET}")

    tech = header_data["technologies"]
    print(f"\n[+] Cabeceras de infraestructura:")
    print(f"  - Server       : {tech['server']}")
    print(f"  - X-Powered-By : {tech['x_powered_by']}")
    for k, v in tech.get("all_exposed_headers", {}).items():
        if k not in ("Server", "X-Powered-By"):
            print(f"  - {k:<12} : {v}")

    print(f"\n[+] Cabeceras de seguridad activas ({len(header_data['present_security_headers'])}):")
    if header_data["present_security_headers"]:
        for h, val in header_data["present_security_headers"].items():
            short_val = val if len(val) <= 72 else val[:69] + "..."
            print(f"  {C.GREEN}[OK]{C.RESET} {h}: {short_val}")
    else:
        print(f"  {C.RED}- Ninguna cabecera de seguridad detectada.{C.RESET}")

    if header_data["header_warnings"]:
        print(f"\n[!] Advertencias de configuración en cabeceras ({len(header_data['header_warnings'])}):")
        for warn in header_data["header_warnings"]:
            print(f"  {C.YELLOW}[WARN]{C.RESET} {warn}")

    if header_data["missing_security_headers"]:
        print(f"\n[-] Cabeceras de seguridad ausentes ({len(header_data['missing_security_headers'])}):")
        for h, desc in header_data["missing_security_headers"].items():
            print(f"  {C.RED}[MISSING]{C.RESET} {h} -> {desc}")

    cookies = header_data.get("cookies_analysis", [])
    print(f"\n[+] Análisis de Cookies ({len(cookies)}):")
    if cookies:
        for c in cookies:
            status = f"{C.GREEN}[OK]{C.RESET}" if not c["issues"] else f"{C.YELLOW}[WARN]{C.RESET}"
            print(f"  {status} Cookie '{c['name']}' (Secure={c['secure']}, HttpOnly={c['httponly']}, SameSite={c['samesite']})")
            for issue in c["issues"]:
                print(f"         * {issue}")
    else:
        print("  - No se recibieron cabeceras Set-Cookie en esta respuesta.")

    print(f"\n{C.CYAN}{'=' * 70}{C.RESET}")
    print(f"{C.BOLD} [*] 3. ANÁLISIS DE CÓDIGO FUENTE, SRI Y SUPERFICIE WEB{C.RESET}")
    print(f"{C.CYAN}{'=' * 70}{C.RESET}")

    print(f"\n[!] Subdominios detectados ({len(page_data['subdomains'])}):")
    if page_data["subdomains"]:
        for s in page_data["subdomains"]:
            print(f"  - {s}")
    else:
        print("  - No se detectaron subdominios adicionales.")

    print(f"\n[!] Correos electrónicos ({len(page_data['emails'])}):")
    if page_data["emails"]:
        for m in page_data["emails"]:
            print(f"  - {m}")
    else:
        print("  - No se detectaron correos electrónicos expuestos.")

    print(f"\n[!] Integridad de Subrecursos Externos - SRI ({len(page_data['missing_sri'])} sin integrity):")
    if page_data["missing_sri"]:
        for item in page_data["missing_sri"]:
            print(f"  {C.YELLOW}[SIN SRI]{C.RESET} <{item['tag']}> {item['url']}")
    else:
        print(f"  {C.GREEN}[OK]{C.RESET} Todos los recursos de CDNs externos usan Subresource Integrity (o son locales).")

    print(f"\n[!] Posibles Secretos / Tokens expuestos ({len(page_data['secrets'])} categorías):")
    if page_data["secrets"]:
        for sec_type, hits in page_data["secrets"].items():
            print(f"  {C.RED}[ALERTA] {sec_type}:{C.RESET}")
            for item in hits:
                masked = item if len(item) < 15 else item[:8] + "..." + item[-4:]
                print(f"    * {masked}")
    else:
        print(f"  {C.GREEN}[OK]{C.RESET} No se detectaron patrones conocidos de claves o tokens en el HTML.")

    print(f"\n[!] Endpoints y Rutas de aplicación ({len(page_data['endpoints'])}):")
    for ep in page_data["endpoints"][:30]:
        print(f"  - {ep}")
    if len(page_data["endpoints"]) > 30:
        print(f"  ... y {len(page_data['endpoints']) - 30} endpoints más.")

    if page_data["forms"]:
        print(f"\n[!] Formularios HTML detectados ({len(page_data['forms'])}):")
        for idx, form in enumerate(page_data["forms"], 1):
            warn_str = f" | {C.YELLOW}Alertas: {', '.join(form['warnings'])}{C.RESET}" if form["warnings"] else f" | {C.GREEN}OK{C.RESET}"
            print(f"  [{idx}] {form['method']} -> {form['action']} ({len(form['inputs'])} inputs){warn_str}")

    print(f"\n[!] Comentarios en HTML y JS inline ({len(page_data['comments'])}):")
    for idx, c in enumerate(page_data["comments"][:20], 1):
        single_line = " ".join(c.split())
        preview = single_line if len(single_line) < 115 else single_line[:112] + "..."
        print(f"  [{idx}] {preview}")
    if len(page_data["comments"]) > 20:
        print(f"  ... y {len(page_data['comments']) - 20} comentarios más.")

    if aux_data:
        print(f"\n{C.CYAN}{'=' * 70}{C.RESET}")
        print(f"{C.BOLD} [*] 4. ARCHIVOS AUXILIARES (robots.txt / security.txt / sitemap.xml){C.RESET}")
        print(f"{C.CYAN}{'=' * 70}{C.RESET}")
        robots = aux_data["robots_txt"]
        sec_txt = aux_data["security_txt"]
        sitemap = aux_data["sitemap_xml"]
        print(f"  - robots.txt   : {'Encontrado' if robots['present'] else 'No disponible'} ({robots['url']})")
        if robots["disallowed_paths"]:
            print(f"    Rutas Disallow ({len(robots['disallowed_paths'])}): {', '.join(robots['disallowed_paths'][:10])}")
        print(f"  - security.txt : {'Encontrado' if sec_txt['present'] else 'No disponible'} ({sec_txt['url']})")
        print(f"  - sitemap.xml  : {'Encontrado (' + str(sitemap['urls_count']) + ' URLs)' if sitemap['present'] else 'No disponible'} ({sitemap['url']})")

    if js_data and js_data.get("scanned_files"):
        print(f"\n{C.CYAN}{'=' * 70}{C.RESET}")
        print(f"{C.BOLD} [*] 5. ESCANEO DE ARCHIVOS JAVASCRIPT ({len(js_data['scanned_files'])} analizados){C.RESET}")
        print(f"{C.CYAN}{'=' * 70}{C.RESET}")
        if js_data["secrets"]:
            for sec_type, hits in js_data["secrets"].items():
                print(f"  {C.RED}[ALERTA JS] {sec_type}: {len(hits)} hallazgo(s){C.RESET}")
        else:
            print(f"  {C.GREEN}[OK]{C.RESET} Sin secretos detectados en los archivos JS analizados.")
        if js_data["api_endpoints"]:
            print(f"  - Endpoints API en JS ({len(js_data['api_endpoints'])}):")
            for ep in js_data["api_endpoints"][:15]:
                print(f"    * {ep}")

    if crawl_data and crawl_data.get("pages_crawled"):
        print(f"\n{C.CYAN}{'=' * 70}{C.RESET}")
        print(f"{C.BOLD} [*] 6. RASTREO DE SUBPÁGINAS INTERNAS ({len(crawl_data['pages_crawled'])} visitadas){C.RESET}")
        print(f"{C.CYAN}{'=' * 70}{C.RESET}")
        for p in crawl_data["pages_crawled"]:
            sec_tag = f", {C.RED}Secretos: {p['secrets_count']}{C.RESET}" if p.get("secrets_count") else ""
            print(
                f"  - [{p['status_code']}] {p['url']} "
                f"(Formularios: {p['forms_count']}, Comentarios: {p['comments_count']}{sec_tag})"
            )

        if crawl_data.get("discovered_secrets"):
            print(f"\n  {C.RED}{C.BOLD}[!] Secretos descubiertos en subpáginas:{C.RESET}")
            for sec_type, hits in crawl_data["discovered_secrets"].items():
                print(f"    {C.RED}[ALERTA CRAWL] {sec_type}:{C.RESET}")
                for item in hits:
                    masked = item if len(item) < 15 else item[:8] + "..." + item[-4:]
                    print(f"      * {masked}")

        if crawl_data.get("discovered_emails"):
            print(f"\n  [!] Correos descubiertos en subpáginas ({len(crawl_data['discovered_emails'])}):")
            for em in crawl_data["discovered_emails"]:
                print(f"    - {em}")

        if crawl_data.get("discovered_forms"):
            print(f"\n  [!] Formularios descubiertos en subpáginas ({len(crawl_data['discovered_forms'])}):")
            for idx, form in enumerate(crawl_data["discovered_forms"], 1):
                warn_str = (
                    f" | {C.YELLOW}Alertas: {', '.join(form['warnings'])}{C.RESET}"
                    if form.get("warnings")
                    else f" | {C.GREEN}OK{C.RESET}"
                )
                print(f"    [{idx}] {form['method']} -> {form['action']} ({len(form['inputs'])} inputs){warn_str}")


def main():
    parser = argparse.ArgumentParser(
        description="Auditor web pasivo: cabeceras OWASP, TLS, SRI, cookies, secretos, formularios, JS y reportes JSON/HTML."
    )
    parser.add_argument("-u", "--url", required=True, help="URL objetivo (ej. https://ejemplo.com)")
    parser.add_argument("-o", "--output", help="Ruta de archivo JSON donde guardar el informe completo.")
    parser.add_argument("--html", help="Ruta de archivo HTML donde generar el reporte visual ejecutivo (ej. reporte.html).")
    parser.add_argument("-t", "--timeout", type=int, default=12, help="Tiempo máximo de espera en segundos (por defecto: 12).")
    parser.add_argument("--crawl", type=int, default=0, metavar="N", help="Visitar hasta N subpáginas internas descubiertas (ej. --crawl 5).")
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="User-Agent personalizado para las peticiones HTTP.")
    parser.add_argument("--insecure", action="store_true", help="Ignorar errores de validación de certificados SSL/TLS.")
    parser.add_argument("--scan-js", action="store_true", help="Analizar también archivos JavaScript locales en busca de secretos y endpoints.")
    parser.add_argument("--no-aux", action="store_true", help="Omitir la consulta de robots.txt, security.txt y sitemap.xml.")
    parser.add_argument("--no-color", action="store_true", help="Desactivar colores ANSI en la terminal.")
    args = parser.parse_args()

    if args.no_color:
        Colors.disable()
    else:
        enable_windows_ansi()

    target_url = args.url.strip()
    parsed_url = urlparse(target_url)
    if not parsed_url.scheme or not parsed_url.netloc:
        print("[-] Formato de URL inválido. Incluye http:// o https:// (ej. https://ejemplo.com)", file=sys.stderr)
        sys.exit(1)

    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    verify_ssl = not args.insecure
    domain = parsed_url.netloc.split(":")[0]

    session = requests.Session()
    session.headers.update({
        "User-Agent": args.user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "es-MX,es;q=0.9,en;q=0.8"
    })

    try:
        response = session.get(target_url, timeout=args.timeout, verify=verify_ssl)
    except requests.exceptions.SSLError as ssl_err:
        print(
            f"[-] Error de certificado SSL al conectar con {target_url}: {ssl_err}\n"
            f"    Sugerencia: Usa la bandera --insecure si deseas auditar un entorno con certificado autofirmado.",
            file=sys.stderr
        )
        sys.exit(1)
    except requests.exceptions.RequestException as error:
        print(f"[-] Error al conectar con {target_url}: {error}", file=sys.stderr)
        sys.exit(1)

    redirect_chain = [r.url for r in response.history] + ([response.url] if response.history else [])
    final_url = response.url
    final_host = urlparse(final_url).netloc.split(":")[0]

    tls_result = None
    if urlparse(final_url).scheme == "https":
        tls_result = inspect_tls_certificate(final_host, 443, min(args.timeout, 8))

    san_domains = tls_result.get("san_domains", []) if tls_result else []

    page_result = parse_page(
        response.text,
        final_host,
        final_url,
        dict(response.headers),
        san_domains
    )
    headers_result = analyze_headers(response, page_result["meta_generators"])

    aux_result = None
    if not args.no_aux:
        aux_result = check_auxiliary_files(session, final_url, args.timeout, verify_ssl)

    js_result = None
    if args.scan_js:
        js_result = scan_javascript_files(
            session,
            page_result["static_assets"],
            args.timeout,
            verify_ssl
        )

    crawl_result = None
    if args.crawl > 0:
        crawl_result = crawl_subpages(
            session,
            page_result["endpoints"],
            final_url,
            page_result["root_domain"],
            args.crawl,
            args.timeout,
            verify_ssl
        )

    print_terminal_results(
        final_url,
        response.status_code,
        redirect_chain,
        headers_result,
        page_result,
        tls_result,
        aux_result,
        js_result,
        crawl_result
    )

    full_report = {
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "target_url": target_url,
        "final_url": final_url,
        "redirect_chain": redirect_chain,
        "domain": final_host,
        "root_domain": page_result["root_domain"],
        "status_code": response.status_code,
        "tls_analysis": tls_result,
        "headers_analysis": headers_result,
        "recon_data": page_result,
        "auxiliary_files": aux_result,
        "js_analysis": js_result,
        "crawl_analysis": crawl_result
    }

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(full_report, f, indent=4, ensure_ascii=False)
            print(f"\n{Colors.GREEN}[+] Informe JSON guardado con éxito en: {args.output}{Colors.RESET}")
        except OSError as e:
            print(f"[-] Error al guardar el archivo JSON: {e}", file=sys.stderr)

    if args.html:
        try:
            generate_html_report(full_report, args.html)
            print(f"{Colors.GREEN}[+] Reporte visual HTML generado con éxito en: {args.html}{Colors.RESET}")
        except OSError as e:
            print(f"[-] Error al guardar el reporte HTML: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
