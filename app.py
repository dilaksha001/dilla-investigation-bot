import json
import datetime
import socket
import os
import threading
from flask import Flask, request
from user_agents import parse

# Initialize Flask app
app = Flask(__name__)

# Configure the log file. Use an environment variable for production flexibility.
# If WEBHOOK_LOG_FILE is not set, it defaults to 'webhook_logs.json'.
LOG_FILE = os.environ.get('WEBHOOK_LOG_FILE', 'webhook_logs.json')

# Create a lock for thread-safe file writing. This prevents data corruption when multiple requests
# try to write to the log file simultaneously.
LOG_LOCK = threading.Lock()

def perform_reverse_dns(ip_address):
    """
    Performs a reverse DNS lookup for a given IP address.
    Returns the hostname if found, otherwise 'Unknown' or an error message.
    """
    try:
        # socket.gethostbyaddr attempts to resolve an IP address to a hostname.
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror:
        # Host not found error (common if no PTR record exists)
        return "Unknown"
    except socket.timeout:
        # Handle potential timeouts during DNS lookup
        return "Timeout"
    except Exception as e:
        # Catch any other potential errors
        return f"Error: {e}"

@app.route('/',

methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
@app.route('/webhook', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def webhook_listener():
    """
    Main webhook listener endpoint.
    Captures, analyzes, and logs incoming HTTP requests.
    """
    # Record the exact time the request was received
    timestamp = datetime.datetime.now().isoformat()
    
    # 1. Capture every possible HTTP header.
    # request.headers is a Werkzeug Headers object, which behaves like a dictionary.
    # We convert it to a standard Python dictionary for easier serialization.
    headers = {k: v for k, v in request.headers.items()}
    
    # 2. Extract and log the raw body of the request (JSON or Plaintext).
    raw_body = request.data.decode('utf-8', errors='ignore') # Decode raw bytes to UTF-8 string
    body_json = None
    try:
        # Check if Flask identifies the content as JSON and parse it.
        if request.is_json:
            body_json = request.get_json()
        elif raw_body:
            # If not explicitly marked as JSON, try to parse it anyway in case content-type is missing.
            body_json = json.loads(raw_body)
    except json.JSONDecodeError:
        # If parsing fails, it's not valid JSON, so we leave body_json as None.
        pass

    # 3. Identify the client's IP address.
    # Prioritize 'X-Forwarded-For' and 'CF-Connecting-IP' as they are commonly used by proxies
    # and load balancers to preserve the original client IP. Fallback to


request.remote_addr.
    client_ip = request.remote_addr
    x_forwarded_for = headers.get('X-Forwarded-For')
    cf_connecting_ip = headers.get('CF-Connecting-IP') # Cloudflare's specific header

    if x_forwarded_for:
        # X-Forwarded-For can contain a comma-separated list of IPs. The first IP is usually the client.
        client_ip = x_forwarded_for.split(',')[0].strip()
    elif cf_connecting_ip:
        # Use Cloudflare's header if present.
        client_ip = cf_connecting_ip

    # 4. Perform a reverse DNS lookup on the requester's IP.
    reverse_dns_hostname = perform_reverse_dns(client_ip)
    
    # 5. Attempt to identify the client's Operating System and Library through the User-Agent string.
    user_agent_string = headers.get('User-Agent', 'N/A')
    ua_parser_result = {
        "os": "Unknown",
        "browser": "Unknown",
        "device": "Unknown",
        "library_or_client": "Unknown" # Custom field to capture specific HTTP clients/libraries
    }
    try:
        # The 'user-agents' library provides robust parsing of User-Agent strings.
        user_agent = parse(user_agent_string)
        ua_parser_result["os"] = user_agent.os.family if user_agent.os.family else "Unknown"
        ua_parser_result["browser"] = user_agent.browser.family if user_agent.browser.family else "Unknown"
        ua_parser_result["device"] = user_agent.device.family if user_agent.device.family else "Unknown"
        
        # Heuristic checks for common HTTP client


libraries.
        lower_ua = user_agent_string.lower()
        if "curl" in lower_ua:
            ua_parser_result["library_or_client"] = "curl"
        elif "python-requests" in lower_ua:
            ua_parser_result["library_or_client"] = "Python Requests"
        elif "go-http-client" in lower_ua:
            ua_parser_result["library_or_client"] = "Go HTTP Client"
        elif "java" in lower_ua and "okhttp" not in lower_ua: # Differentiate generic Java from OkHttp
            ua_parser_result["library_or_client"] = "Java HTTP Client"
        elif "okhttp" in lower_ua:
            ua_parser_result["library_or_client"] = "OkHttp (Java/Kotlin)"
        elif "node" in lower_ua:
            ua_parser_result["library_or_client"] = "Node.js HTTP Client"
        elif "ruby" in lower_ua:
            ua_parser_result["library_or_client"] = "Ruby HTTP Client"
        elif "wget" in lower_ua:
            ua_parser_result["library_or_client"] = "Wget"
        else:
            # Fallback to the browser family if no specific library is identified.
            ua_parser_result["library_or_client"] = user_agent.browser.family if user_agent.browser.family else "Unknown"
            
    except Exception as e:
        # If user-agent parsing fails, log the error.
        ua_parser_result["error"] = str(e)

    # 6. Log all these details into a structured JSON file with timestamps.
    # We will use the JSON Lines (JSONL) format for easier appending and parsing later.
    log_entry = {


"timestamp": timestamp,
        "method": request.method,
        "path": request.path,
        "remote_addr": request.remote_addr, # Original IP seen by Flask
        "client_ip_resolved": client_ip, # Resolved client IP (considering proxies)
        "reverse_dns": reverse_dns_hostname,
        "user_agent_raw": user_agent_string,
        "user_agent_parsed": ua_parser_result,
        "headers": headers,
        "body_raw": raw_body,
        "body_json": body_json
    }

    # Acquire the lock before writing to the file to prevent race conditions.
    with LOG_LOCK:
        try:
            # Open the log file in append mode ('a').
            # Each log entry is written as a single JSON object on a new line.
            with open(LOG_FILE, 'a') as f:
                json.dump(log_entry, f)
                f.write('\n') # Add a newline to separate JSON objects
            print(f"Logged request from {client_ip} method {request.method} to {LOG_FILE}")
        except Exception as e:
            # If logging fails, return an internal server error.
            print(f"ERROR: Failed to write to log file '{LOG_FILE}': {e}")
            return {"status": "error", "message": f"Failed to log request: {e}"}, 500

    # Return a success response to the client.
    return {"status": "success", "message": "Webhook received and logged"}, 200

if __name__ == '__main__':
    # This block runs when the script is executed directly (e.g., python app.py).
    # It's for local development and


testing. In production, a WSGI server like Gunicorn will be used.
    print(f"Starting Flask app locally. Logs will be saved to {LOG_FILE}")
    app.run(host='0.0.0.0', port=5000, debug=True)
