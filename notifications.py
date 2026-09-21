import json
import os
import requests

def send_discord_webhook_v2(webhook_url, target, total_subs, critical=0,
                            high=0, duration=0, json_path=None, pdf_path=None):
    """
    Notificação Enterprise v2: embed com métricas de severidade,
    duração do scan e anexos (JSON bruto + PDF executivo).
    """
    if not webhook_url:
        return False

    # Cor do embed por gravidade: vermelho se crítico, laranja se high, azul ok
    color = 0xED4245 if critical else (0xFEE75C if high else 0x3447003)
    severity_text = (
        f"🔴 {critical} críticos" if critical
        else (f"🟠 {high} high" if high else "🟢 Sem achados críticos/high")
    )

    fields = [
        {"name": "Target", "value": target, "inline": True},
        {"name": "Subdomínios", "value": str(total_subs), "inline": True},
        {"name": "Duração", "value": f"{duration}s", "inline": True},
        {"name": "Severidade", "value": severity_text, "inline": False},
    ]

    files = {}
    if json_path and os.path.exists(json_path):
        files["file1"] = (os.path.basename(json_path), open(json_path, "rb"), "application/json")
    if pdf_path and os.path.exists(pdf_path):
        files["file2"] = (os.path.basename(pdf_path), open(pdf_path, "rb"), "application/pdf")

    payload = {
        "username": "CyShield Engine Enterprise",
        "embeds": [{
            "title": f"🛡️ Scan Enterprise Concluído: {target}",
            "color": color,
            "fields": fields,
            "footer": {"text": "CyShield Engine v2.0 — Enterprise Red Team"},
            "timestamp": datetime.utcnow().isoformat(),
        }],
    }

    try:
        if files:
            files["payload_json"] = (None, json.dumps(payload), "application/json")
            response = requests.post(webhook_url, files=files, timeout=30)
            for f in files.values():
                if f and f[0]:
                    f[1].close()  # fecha os file handles abertos
        else:
            response = requests.post(webhook_url, json=payload, timeout=15)

        if response.status_code in (200, 204):
            print("[NOTIF] Notificação enviada ao Discord com sucesso!")
            return True
        print(f"[NOTIF] Erro no webhook (Status {response.status_code}): {response.text[:200]}")
        return False
    except Exception as e:
        print(f"[NOTIF] Falha no envio do webhook: {e}")
        return False
