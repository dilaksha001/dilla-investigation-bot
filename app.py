import json
import datetime
import socket
import os
import threading
import requests  # IP metadata ලබා ගැනීමට අලුතින් එක් කළා
from flask import Flask, request, jsonify
from user_agents import parse

app = Flask(__name__)

# Configuration
LOG_FILE = os.environ.get('WEBHOOK_LOG_FILE', 'webhook_logs.json')
LOG_LOCK = threading.Lock()

def get_ip_metadata(ip):
    """
    IP ලිපිනය මගින් ISP සහ Location තොරතුරු ලබා ගනී. 
    මෙය Google වෙත වාර්තා කිරීමේදී ඉතා වැදගත් වේ.
    """
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        return response.json()
    except:
        return {"error": "Could not fetch metadata"}

def perform_reverse_dns(ip_address):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except:
        return "Unknown"

@app.route('/webhook_logs.json')
def honeyfile_trap():
    """
    යමෙකු ලොග් ෆයිල් එක සොරකම් කිරීමට උත්සාහ කළහොත් ඔවුන්ව කොටු කරගන්නා ස්ථානය.
    """
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    print(f"⚠️  WARNING: Unauthorized log access attempt from: {client_ip}")
    
    # ඔවුන්ට පෙන්වීමට බොරු දත්ත (Fake Data)
    return jsonify({
        "status": "encrypted",
        "vault_id": "VAULT-HIDDEN-99",
        "message": "Access Denied. Admin alerted."
    }), 403

@app.route('/', methods=['GET', 'POST'])
@app.route('/webhook', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def investigation_listener():
    """
    ප්‍රධාන විමර්ශන endpoint එක. 
    සැබෑ Gemini API එකක් ලෙස පෙනී සිටිමින් දත්ත රැස් කරයි.
    """
    timestamp = datetime.datetime.now().isoformat()
    headers = {k: v for k, v in request.headers.items()}
    raw_body = request.data.decode('utf-8', errors='ignore')
    
    # IP ලිපිනය නිවැරදිව ලබා ගැනීම
    client_ip = headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    
    # වැඩිදුර තොරතුරු (DNS සහ Geolocation)
    reverse_dns = perform_reverse_dns(client_ip)
    ip_meta = get_ip_metadata(client_ip)

    # User-Agent විශ්ලේෂණය
    ua_string = headers.get('User-Agent', 'N/A')
    ua = parse(ua_string)

    log_entry = {
        "timestamp": timestamp,
        "method": request.method,
        "client_ip": client_ip,
        "isp": ip_meta.get('isp', 'Unknown'),
        "country": ip_meta.get('country', 'Unknown'),
        "reverse_dns": reverse_dns,
        "user_agent": {
            "raw": ua_string,
            "os": ua.os.family,
            "browser": ua.browser.family
        },
        "headers": headers,
        "payload": raw_body
    }

    # ලොග් එක සේව් කිරීම
    with LOG_LOCK:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            json.dump(log_entry, f, ensure_ascii=False)
            f.write('\n')
    
    print(f"🚨 ALERT: Data captured from {client_ip} ({ip_meta.get('isp')})")

    # 🎭 Gemini API එකක සැබෑ Response එකක් අනුකරණය කිරීම (The Deception)
    return jsonify({
        "candidates": [{
            "content": {
                "parts": [{"text": "Request processed successfully."}],
                "role": "model"
            }
        }],
        "usageMetadata": {"promptTokenCount": 0, "candidatesTokenCount": 0, "totalTokenCount": 0}
    }), 200

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
