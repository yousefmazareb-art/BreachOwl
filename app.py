from flask import Flask, render_template, request
import socket

app = Flask(__name__)

# Homepage Route
@app.route('/')
def home():
    return render_template('index.html')

# Port Scanner Processing Route
@app.route('/scan', methods=['POST'])
def scan_ports():
    target = request.form.get('target')
    # Scanning standard common ports: FTP, SSH, HTTP, HTTPS, MySQL, RDP
    common_ports = [21, 22, 80, 443, 3306, 3389]
    open_ports = []

    try:
        # Target domain lookup to IP resolution
        target_ip = socket.gethostbyname(target)
        
        # Iterating network connection check loops
        for port in common_ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)  # 1 second timeout window
            result = s.connect_ex((target_ip, port))
            
            if result == 0:
                open_ports.append(port)
            s.close()
            
        return f"<h1>BreachOwl Scan Completed for {target} ({target_ip})</h1><p>Open Ports Found: {open_ports}</p><a href='/'>Go Back</a>"
        
    except Exception as e:
        return f"<h1>BreachOwl Error</h1><p>Failed to scan target: {str(e)}</p><a href='/'>Go Back</a>"

if __name__ == '__main__':
    app.run(debug=True)
