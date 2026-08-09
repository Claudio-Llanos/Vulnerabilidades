import httpx
from datetime import datetime
from zoneinfo import ZoneInfo

MAT_URL    = "https://mat-vpto.clarochile.cl/mat/api/v2/networktask/lw9-etr-ptk/env/sandbox/jobs"
MAT_APIKEY = "CuiGDkmP7lDa0ueqAHg8Eee2ZKyRQTZv"
MAIL_DEST  = ["claudio.llanos@clarovtr.cl", "cristian.trepiana@clarovtr.cl"]

def now_chile():
    return datetime.now(ZoneInfo("America/Santiago")).strftime("%d/%m/%Y %H:%M")

async def send_mail(subject: str, plain: str, html: str):
    payload = {
        "form_data": {
            "dest":       MAIL_DEST,
            "subject":    subject,
            "plain_body": plain,
            "html_body":  html,
        }
    }
    try:
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            await client.post(
                MAT_URL,
                json=payload,
                headers={"Content-Type": "application/json", "apikey": MAT_APIKEY}
            )
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")

async def mail_evento(evento: str, vuln_id: int, detalle: str,
                      usuario: str, cambios: list, extra: str = ""):
    ts      = now_chile()
    subject = f"[GoC Vulnerabilidades] {evento} — #{vuln_id}"

    rows_plain = "\n".join(f"  - {c}" for c in cambios)
    plain = (
        f"GoC Gestion de Vulnerabilidades\n"
        f"{'='*48}\n"
        f"Evento   : {evento}\n"
        f"Registro : #{vuln_id} - {detalle}\n"
        f"Usuario  : {usuario}\n"
        f"Fecha    : {ts}\n"
        f"{'='*48}\n"
        f"{rows_plain}\n"
    )
    if extra:
        plain += f"\nDetalle adicional:\n{extra}"

    rows_html = "".join(
        f"<tr><td style='padding:6px 12px;border-bottom:1px solid #eee'>{c}</td></tr>"
        for c in cambios
    )

    html = (
        "<div style='font-family:Arial,sans-serif;max-width:600px'>"
        "<div style='background:#DA0812;padding:14px 20px'>"
        "<h2 style='color:#fff;margin:0;font-size:16px'>GoC - Gestion de Vulnerabilidades</h2>"
        "</div>"
        "<div style='padding:20px;background:#f9f9f9'>"
        "<table style='width:100%;border-collapse:collapse;margin-bottom:16px'>"
        f"<tr><td style='padding:4px 0;color:#666;width:120px'>Evento</td>"
        f"<td style='padding:4px 0;font-weight:600'>{evento}</td></tr>"
        f"<tr><td style='padding:4px 0;color:#666'>Registro</td>"
        f"<td style='padding:4px 0;font-weight:600'>#{vuln_id} - {detalle[:80]}</td></tr>"
        f"<tr><td style='padding:4px 0;color:#666'>Usuario</td>"
        f"<td style='padding:4px 0'>{usuario}</td></tr>"
        f"<tr><td style='padding:4px 0;color:#666'>Fecha</td>"
        f"<td style='padding:4px 0'>{ts}</td></tr>"
        "</table>"
        "<table style='width:100%;border-collapse:collapse;background:#fff;border:1px solid #eee'>"
        "<thead><tr><th style='background:#DA0812;color:#fff;padding:8px 12px;text-align:left'>"
        "Cambios realizados</th></tr></thead>"
        f"<tbody>{rows_html}</tbody>"
        "</table>"
        + (f"<p style='margin-top:12px;color:#555'>{extra}</p>" if extra else "")
        + "</div>"
        "<div style='padding:10px 20px;background:#eee;font-size:11px;color:#999'>"
        "Sistema de Gestion de Vulnerabilidades - Claro GoC Ingenieria"
        "</div></div>"
    )

    await send_mail(subject, plain, html)
