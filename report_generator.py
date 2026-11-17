import html
from typing import Any


def _score_grade(score: int) -> tuple[str, str]:
    if score >= 90:
        return "A", "#10b981"
    if score >= 75:
        return "B", "#3b82f6"
    if score >= 55:
        return "C", "#f59e0b"
    if score >= 35:
        return "D", "#f97316"
    return "F", "#ef4444"


def _esc(val: Any) -> str:
    return html.escape(str(val)) if val is not None else ""


def generate_html_report(report: dict[str, Any], output_path: str) -> None:
    """Genera un informe ejecutivo e interactivo en formato HTML listo para navegador o impresión PDF."""
    headers_info = report.get("headers_analysis", {})
    recon = report.get("recon_data", {})
    tls_info = report.get("tls_analysis") or {}
    aux_info = report.get("auxiliary_files") or {}
    js_info = report.get("js_analysis") or {}
    crawl_info = report.get("crawl_analysis") or {}

    score = headers_info.get("security_score", 0)
    grade, badge_color = _score_grade(score)

    present_headers = headers_info.get("present_security_headers", {})
    missing_headers = headers_info.get("missing_security_headers", {})
    header_warnings = headers_info.get("header_warnings", [])
    cookies = headers_info.get("cookies_analysis", [])
    fingerprints = headers_info.get("detected_stack", [])

    subdomains = recon.get("subdomains", [])
    emails = recon.get("emails", [])
    endpoints = recon.get("endpoints", [])
    forms = recon.get("forms", [])
    sri_missing = recon.get("missing_sri", [])
    comments = recon.get("comments", [])
    secrets = recon.get("secrets", {})

    # Construcción de filas de cabeceras presentes
    present_rows = ""
    for h_name, h_val in present_headers.items():
        present_rows += f"""
        <tr>
            <td><span class="badge badge-ok">ACTIVA</span></td>
            <td><strong>{_esc(h_name)}</strong></td>
            <td class="mono">{_esc(h_val)}</td>
        </tr>"""
    for h_name, h_desc in missing_headers.items():
        present_rows += f"""
        <tr>
            <td><span class="badge badge-danger">AUSENTE</span></td>
            <td><strong>{_esc(h_name)}</strong></td>
            <td class="muted">{_esc(h_desc)}</td>
        </tr>"""

    # Advertencias de configuración
    warnings_html = ""
    if header_warnings:
        items = "".join(f"<li>{_esc(w)}</li>" for w in header_warnings)
        warnings_html = f"""
        <div class="alert alert-warn">
            <h4>⚠️ Advertencias de configuración en cabeceras ({len(header_warnings)})</h4>
            <ul>{items}</ul>
        </div>"""
    else:
        warnings_html = '<div class="alert alert-ok">✅ No se detectaron directivas inseguras en las cabeceras presentes.</div>'

    # Cookies
    cookies_rows = ""
    if cookies:
        for c in cookies:
            status_badge = '<span class="badge badge-ok">SEGURA</span>' if not c.get("issues") else '<span class="badge badge-warn">RIESGO</span>'
            issues_str = "<br>".join(_esc(i) for i in c.get("issues", [])) or "Configuración óptima"
            cookies_rows += f"""
            <tr>
                <td>{status_badge}</td>
                <td><strong>{_esc(c.get('name'))}</strong></td>
                <td>{"✅" if c.get("secure") else "❌"}</td>
                <td>{"✅" if c.get("httponly") else "❌"}</td>
                <td><code>{_esc(c.get('samesite'))}</code></td>
                <td>{issues_str}</td>
            </tr>"""
    else:
        cookies_rows = '<tr><td colspan="6" class="muted">No se recibieron cookies (Set-Cookie) en la respuesta HTTP.</td></tr>'

    # TLS / SSL
    tls_html = ""
    if tls_info.get("enabled"):
        days_left = tls_info.get("days_remaining")
        days_badge = "badge-ok" if (days_left is not None and days_left > 30) else "badge-warn"
        tls_warns = "".join(f"<li>{_esc(w)}</li>" for w in tls_info.get("warnings", []))
        san_list = ", ".join(f"<code>{_esc(s)}</code>" for s in tls_info.get("san_domains", [])[:25]) or "Ninguno"
        tls_html = f"""
        <div class="grid-2">
            <div>
                <p><strong>Protocolo negociado:</strong> <code>{_esc(tls_info.get('protocol_version'))}</code></p>
                <p><strong>Suite de cifrado:</strong> <code>{_esc(tls_info.get('cipher_suite'))}</code> ({_esc(tls_info.get('cipher_bits'))} bits)</p>
                <p><strong>Emisor (CA):</strong> {_esc(tls_info.get('issuer'))}</p>
            </div>
            <div>
                <p><strong>Sujeto (CN):</strong> <code>{_esc(tls_info.get('subject'))}</code></p>
                <p><strong>Válido hasta:</strong> {_esc(tls_info.get('not_after'))} <span class="badge {days_badge}">{_esc(days_left)} días restantes</span></p>
                <p><strong>Dominios SAN ({len(tls_info.get('san_domains', []))}):</strong> {san_list}</p>
            </div>
        </div>
        {f'<div class="alert alert-warn"><ul>{tls_warns}</ul></div>' if tls_warns else ''}
        """
    else:
        tls_html = f'<p class="muted">Inspección TLS no disponible: {_esc(tls_info.get("error", "Sitio HTTP o sin conexión TLS"))}</p>'

    # SRI (Subresource Integrity)
    sri_rows = ""
    if sri_missing:
        for item in sri_missing:
            sri_rows += f"""
            <tr>
                <td><span class="badge badge-warn">SIN SRI</span></td>
                <td><code>&lt;{_esc(item.get('tag'))}&gt;</code></td>
                <td class="mono">{_esc(item.get('url'))}</td>
            </tr>"""
    else:
        sri_rows = '<tr><td colspan="3" class="muted">✅ Todos los scripts y hojas de estilo de CDNs externos cuentan con atributo integrity (o no se usan CDNs externos).</td></tr>'

    # Formularios
    forms_rows = ""
    if forms:
        for f in forms:
            f_warns = f.get("warnings", [])
            f_badge = '<span class="badge badge-warn">REVISAR</span>' if f_warns else '<span class="badge badge-ok">OK</span>'
            inputs_desc = ", ".join(f"{_esc(i.get('name') or '(sin nombre)')} [{_esc(i.get('type'))}]" for i in f.get("inputs", [])) or "Sin campos"
            forms_rows += f"""
            <tr>
                <td>{f_badge}</td>
                <td><code>{_esc(f.get('method'))}</code></td>
                <td class="mono">{_esc(f.get('action'))}</td>
                <td>{inputs_desc}</td>
                <td>{"<br>".join(_esc(w) for w in f_warns) or "Sin alertas"}</td>
            </tr>"""
    else:
        forms_rows = '<tr><td colspan="5" class="muted">No se detectaron formularios HTML en la página.</td></tr>'

    # Secretos
    secrets_html = ""
    if secrets:
        sec_items = ""
        for s_type, hits in secrets.items():
            masked_list = ", ".join(f"<code>{_esc(h if len(h) < 15 else h[:8] + '...' + h[-4:])}</code>" for h in hits)
            sec_items += f"<li><strong>{_esc(s_type)}:</strong> {masked_list}</li>"
        secrets_html = f'<div class="alert alert-danger"><h4>🚨 Posibles Secretos o Tokens Expuestos</h4><ul>{sec_items}</ul></div>'
    else:
        secrets_html = '<div class="alert alert-ok">✅ No se detectaron claves API, tokens JWT ni llaves privadas expuestas en el HTML.</div>'

    # Subdominios y Endpoints
    subdomains_html = "".join(f"<li><code>{_esc(s)}</code></li>" for s in subdomains) or '<li class="muted">Ningún subdominio adicional detectado.</li>'
    endpoints_html = "".join(f'<li><a href="{_esc(ep)}" target="_blank" rel="noopener">{_esc(ep)}</a></li>' for ep in endpoints[:60]) or '<li class="muted">Sin rutas internas detectadas.</li>'

    # Comentarios
    comments_rows = ""
    if comments:
        for idx, c in enumerate(comments[:35], 1):
            preview = c if len(c) <= 350 else c[:347] + "..."
            comments_rows += f"""
            <tr>
                <td><code>#{idx}</code></td>
                <td class="mono">{_esc(preview)}</td>
            </tr>"""
    else:
        comments_rows = '<tr><td colspan="2" class="muted">No se encontraron comentarios en el código fuente.</td></tr>'

    # Rastreo (Crawl)
    crawl_section = ""
    if crawl_info and crawl_info.get("pages_crawled"):
        c_rows = ""
        for p in crawl_info["pages_crawled"]:
            c_rows += f"""
            <tr>
                <td><code>{_esc(p.get('status_code'))}</code></td>
                <td class="mono">{_esc(p.get('url'))}</td>
                <td>{_esc(p.get('forms_count', 0))}</td>
                <td>{_esc(p.get('comments_count', 0))}</td>
                <td>{_esc(p.get('secrets_count', 0))}</td>
            </tr>"""
        crawl_section = f"""
        <section class="card">
            <h2>7. Rastreo de Subpáginas Internas (--crawl)</h2>
            <table>
                <thead>
                    <tr>
                        <th>Estado</th>
                        <th>URL Visitada</th>
                        <th>Formularios</th>
                        <th>Comentarios</th>
                        <th>Secretos</th>
                    </tr>
                </thead>
                <tbody>{c_rows}</tbody>
            </table>
        </section>"""

    stack_badges = "".join(f'<span class="tech-pill">{_esc(t)}</span>' for t in fingerprints) or '<span class="muted">No identificado</span>'

    html_doc = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Auditoría Web - {_esc(report.get('domain'))}</title>
    <style>
        :root {{
            --bg: #0f172a;
            --card: #1e293b;
            --border: #334155;
            --text: #f8fafc;
            --muted: #94a3b8;
            --accent: #38bdf8;
        }}
        * {{ box-sizing: border-box; }}
        body {{
            margin: 0;
            padding: 32px 20px;
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.55;
        }}
        .container {{ max-width: 1120px; margin: 0 auto; }}
        header.hero {{
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            align-items: center;
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 24px 28px;
            margin-bottom: 24px;
        }}
        .hero h1 {{ margin: 0 0 6px 0; font-size: 1.65rem; color: var(--accent); }}
        .hero p {{ margin: 4px 0; color: var(--muted); font-size: 0.95rem; }}
        .score-box {{
            text-align: center;
            background: rgba(15, 23, 42, 0.75);
            border: 2px solid {badge_color};
            border-radius: 12px;
            padding: 14px 24px;
            min-width: 150px;
        }}
        .score-grade {{ font-size: 2.4rem; font-weight: 800; color: {badge_color}; line-height: 1; }}
        .score-num {{ font-size: 0.9rem; color: var(--muted); margin-top: 4px; }}
        .card {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 22px 24px;
            margin-bottom: 22px;
        }}
        .card h2 {{
            margin-top: 0;
            font-size: 1.2rem;
            border-bottom: 1px solid var(--border);
            padding-bottom: 10px;
            color: #e2e8f0;
        }}
        .grid-2 {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 18px;
        }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 14px;
            margin-bottom: 22px;
        }}
        .kpi {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 14px 16px;
            text-align: center;
        }}
        .kpi .num {{ font-size: 1.6rem; font-weight: 700; color: var(--accent); }}
        .kpi .lbl {{ font-size: 0.82rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
            margin-top: 10px;
        }}
        th, td {{
            text-align: left;
            padding: 10px 12px;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
            word-break: break-word;
        }}
        th {{ color: var(--muted); font-weight: 600; background: rgba(15, 23, 42, 0.45); }}
        .mono {{ font-family: Consolas, 'Courier New', monospace; font-size: 0.84rem; color: #cbd5e1; }}
        .muted {{ color: var(--muted); }}
        .badge {{
            display: inline-block;
            padding: 3px 9px;
            border-radius: 999px;
            font-size: 0.74rem;
            font-weight: 700;
            letter-spacing: 0.03em;
        }}
        .badge-ok {{ background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }}
        .badge-warn {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }}
        .badge-danger {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }}
        .tech-pill {{
            display: inline-block;
            background: rgba(56, 189, 248, 0.14);
            color: #7dd3fc;
            border: 1px solid rgba(56, 189, 248, 0.35);
            padding: 4px 11px;
            border-radius: 6px;
            font-size: 0.84rem;
            margin: 3px 6px 3px 0;
        }}
        .alert {{
            border-radius: 10px;
            padding: 14px 18px;
            margin-top: 14px;
            font-size: 0.92rem;
        }}
        .alert h4 {{ margin: 0 0 8px 0; }}
        .alert ul {{ margin: 0; padding-left: 20px; }}
        .alert-warn {{ background: rgba(245, 158, 11, 0.12); border: 1px solid rgba(245, 158, 11, 0.4); color: #fde68a; }}
        .alert-danger {{ background: rgba(239, 68, 68, 0.12); border: 1px solid rgba(239, 68, 68, 0.4); color: #fecaca; }}
        .alert-ok {{ background: rgba(16, 185, 129, 0.12); border: 1px solid rgba(16, 185, 129, 0.4); color: #a7f3d0; }}
        a {{ color: var(--accent); text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        ul.compact {{ max-height: 260px; overflow-y: auto; padding-left: 20px; margin: 8px 0; }}
        @media print {{
            :root {{ --bg: #ffffff; --card: #ffffff; --border: #cbd5e1; --text: #0f172a; --muted: #475569; --accent: #0284c7; }}
            body {{ padding: 0; }}
            .mono {{ color: #1e293b; }}
            .card, header.hero {{ break-inside: avoid; box-shadow: none; }}
            ul.compact {{ max-height: none; overflow: visible; }}
        }}
    </style>
</head>
<body>
<div class="container">
    <header class="hero">
        <div>
            <h1>🛡️ Reporte de Auditoría de Seguridad Web</h1>
            <p><strong>URL Objetivo:</strong> <a href="{_esc(report.get('final_url'))}" target="_blank">{_esc(report.get('final_url'))}</a> (HTTP {_esc(report.get('status_code'))})</p>
            <p><strong>Dominio Raíz:</strong> <code>{_esc(report.get('root_domain'))}</code> | <strong>Fecha UTC:</strong> {_esc(report.get('scan_timestamp'))}</p>
            <p style="margin-top:10px;"><strong>Stack Detectado:</strong> {stack_badges}</p>
        </div>
        <div class="score-box">
            <div class="score-grade">{grade}</div>
            <div class="score-num">Puntaje: {score}/100</div>
        </div>
    </header>

    <div class="kpi-grid">
        <div class="kpi"><div class="num">{len(present_headers)}/{len(present_headers) + len(missing_headers)}</div><div class="lbl">Cabeceras OWASP</div></div>
        <div class="kpi"><div class="num">{len(header_warnings)}</div><div class="lbl">Alertas Config</div></div>
        <div class="kpi"><div class="num">{len(subdomains)}</div><div class="lbl">Subdominios</div></div>
        <div class="kpi"><div class="num">{len(endpoints)}</div><div class="lbl">Endpoints</div></div>
        <div class="kpi"><div class="num">{len(sri_missing)}</div><div class="lbl">CDN sin SRI</div></div>
        <div class="kpi"><div class="num">{len(comments)}</div><div class="lbl">Comentarios</div></div>
    </div>

    <section class="card">
        <h2>1. Auditoría de Cabeceras de Seguridad HTTP (OWASP)</h2>
        {warnings_html}
        <table>
            <thead>
                <tr>
                    <th style="width:110px;">Estado</th>
                    <th style="width:240px;">Cabecera</th>
                    <th>Valor / Descripción</th>
                </tr>
            </thead>
            <tbody>{present_rows}</tbody>
        </table>
    </section>

    <section class="card">
        <h2>2. Inspección de Certificado SSL/TLS y Cifrado</h2>
        {tls_html}
    </section>

    <section class="card">
        <h2>3. Auditoría de Cookies (Set-Cookie)</h2>
        <table>
            <thead>
                <tr>
                    <th>Estado</th>
                    <th>Cookie</th>
                    <th>Secure</th>
                    <th>HttpOnly</th>
                    <th>SameSite</th>
                    <th>Observaciones</th>
                </tr>
            </thead>
            <tbody>{cookies_rows}</tbody>
        </table>
    </section>

    <section class="card">
        <h2>4. Integridad de Subrecursos Externos (SRI) y Formularios HTML</h2>
        <h3>Recursos de CDNs externos sin atributo <code>integrity</code> (OWASP A08)</h3>
        <table>
            <thead>
                <tr>
                    <th style="width:110px;">Estado</th>
                    <th style="width:110px;">Etiqueta</th>
                    <th>URL del Recurso Externo</th>
                </tr>
            </thead>
            <tbody>{sri_rows}</tbody>
        </table>

        <h3 style="margin-top:22px;">Formularios HTML Detectados</h3>
        <table>
            <thead>
                <tr>
                    <th style="width:110px;">Estado</th>
                    <th style="width:90px;">Método</th>
                    <th>Action URL</th>
                    <th>Campos (Inputs)</th>
                    <th>Alertas</th>
                </tr>
            </thead>
            <tbody>{forms_rows}</tbody>
        </table>
    </section>

    <section class="card">
        <h2>5. Superficie de Ataque, Subdominios y Secretos</h2>
        {secrets_html}
        <div class="grid-2" style="margin-top:16px;">
            <div>
                <h3>Subdominios Descubiertos ({len(subdomains)})</h3>
                <ul class="compact">{subdomains_html}</ul>
                <h3>Correos Electrónicos ({len(emails)})</h3>
                <ul class="compact">{"".join(f"<li><code>{_esc(e)}</code></li>" for e in emails) or '<li class="muted">Ninguno detectado.</li>'}</ul>
            </div>
            <div>
                <h3>Endpoints y Rutas de Aplicación ({len(endpoints)})</h3>
                <ul class="compact">{endpoints_html}</ul>
            </div>
        </div>
    </section>

    <section class="card">
        <h2>6. Comentarios de Desarrollo en HTML / JS ({len(comments)})</h2>
        <table>
            <thead>
                <tr>
                    <th style="width:70px;">#</th>
                    <th>Contenido del Comentario</th>
                </tr>
            </thead>
            <tbody>{comments_rows}</tbody>
        </table>
    </section>

    {crawl_section}
</div>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_doc)
