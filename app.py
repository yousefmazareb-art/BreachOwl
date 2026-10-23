import ipaddress
import os
import re
import socket

from flask import Flask, render_template, request

app = Flask(__name__)

# Common ports to check: FTP, SSH, HTTP, HTTPS, MySQL, RDP
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
}
TIMEOUT = 1.0  # seconds per port

# Letters, digits and hyphens separated by dots (a normal hostname)
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)

# Private and internal addresses are blocked unless you opt in.
# Only set this on your own machine, for scanning your own lab.
ALLOW_PRIVATE = os.environ.get("BREACHOWL_ALLOW_PRIVATE") == "1"


def is_valid_target(target):
    """Accept only a plain hostname or IP address, nothing else."""
    if not target or len(target) > 253:
        return False
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return bool(HOSTNAME_RE.match(target))


def is_blocked(ip):
    """Block loopback, private, link-local and other non-public addresses."""
    if ALLOW_PRIVATE:
        return False
    return not ipaddress.ip_address(ip).is_global


def scan_ports(ip):
    open_ports = []
    for port in COMMON_PORTS:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
    return open_ports


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target", "").strip()

    if request.form.get("authorized") != "yes":
        return render_template(
            "index.html",
            error="Confirm that you own this target or have written permission to scan it.",
        ), 400

    if not is_valid_target(target):
        return render_template(
            "index.html", error="Enter a valid hostname or IP address."
        ), 400

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return render_template(
            "index.html", error="Could not resolve that target."
        ), 400

    # Scan the IP we just checked, so the DNS answer cannot change underneath us.
    if is_blocked(ip):
        return render_template(
            "index.html",
            error="Scanning private or internal addresses is disabled.",
        ), 400

    results = [{"port": p, "service": COMMON_PORTS[p]} for p in scan_ports(ip)]
    return render_template(
        "index.html", scanned=True, target=target, ip=ip, results=results
    )


if __name__ == "__main__":
    # Debug mode exposes an interactive console, so it is off unless you ask for it.
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
