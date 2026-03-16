from prometheus_client import Counter, Histogram, Gauge, start_http_server
import time
import socket
import json
from datetime import datetime
try:
    from src.cve_lookup import enrich_scan_results
except ModuleNotFoundError:
    from cve_lookup import enrich_scan_results


# Prometheus metrics
SCANS_TOTAL = Counter(
    'securenet_scans_total',
    'Total number of scans completed'
)

OPEN_PORTS_FOUND = Counter(
    'securenet_open_ports_total',
    'Total number of open ports found across all scans'
)

RISKY_PORTS_FOUND = Counter(
    'securenet_risky_ports_total',
    'Total number of risky ports found'
)

CVES_FOUND = Counter(
    'securenet_cves_total',
    'Total number of CVEs found'
)

SCAN_DURATION = Histogram(
    'securenet_scan_duration_seconds',
    'Time taken to complete a scan'
)

ACTIVE_SCANS = Gauge(
    'securenet_active_scans',
    'Number of scans currently running'
)


# ─────────────────────────────────────────
# KNOWN SERVICES DICTIONARY
# Maps port numbers to service names
# ─────────────────────────────────────────
KNOWN_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    27017: "MongoDB"
}

# ─────────────────────────────────────────
# RISKY PORTS — flag these in reports
# These are commonly exploited ports
# ─────────────────────────────────────────
RISKY_PORTS = [21, 23, 3306, 27017, 6379]


def get_service_name(port: int) -> str:
    """
    Returns the service name for a given port number.
    If unknown, returns 'unknown'.
    """
    return KNOWN_SERVICES.get(port, "unknown")


def is_risky(port: int) -> bool:
    """
    Returns True if a port is considered risky/dangerous to expose.
    Example: port 23 (Telnet) is unencrypted — very risky.
    """
    return port in RISKY_PORTS


def scan_single_port(target_ip: str, port: int, timeout: float = 1.0) -> dict | None:
    """
    Attempts to connect to a single port on a target IP.
    Returns a result dict if open, None if closed.

    How it works:
    - We create a TCP socket (like picking up a phone)
    - We try to connect to the target IP + port (like dialing a number)
    - If connection succeeds → port is OPEN
    - If connection refused/timeout → port is CLOSED
    """
    try:
        # AF_INET = IPv4, SOCK_STREAM = TCP connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # connect_ex returns 0 if connection succeeded
        result = sock.connect_ex((target_ip, port))
        sock.close()

        if result == 0:
            return {
                "port": port,
                "state": "open",
                "service": get_service_name(port),
                "risky": is_risky(port),
                "scanned_at": datetime.now().isoformat()
            }
    except socket.error:
        pass

    return None  # port is closed or filtered


def grab_banner(target_ip: str, port: int) -> str:
    """
    Tries to grab the service banner from an open port.

    What is a banner?
    When you connect to a server, it often says hello and
    identifies itself — like 'SSH-2.0-OpenSSH_8.9'. That's
    a banner. It tells us what software is running.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target_ip, port))
        # Send a basic HTTP request to trigger a response
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        return banner[:200]  # cap at 200 chars
    except Exception:
        return "no banner retrieved"


def scan_ports(target_ip: str, port_range: range) -> list:
    """
    Scans a range of ports on the target IP.
    Returns a list of all open port results.
    """
    open_ports = []
    print(f"\n[*] Scanning {target_ip} — ports {port_range.start} to {port_range.stop - 1}")

    for port in port_range:
        result = scan_single_port(target_ip, port)
        if result:
            print(f"  [+] Port {port}/tcp OPEN — {result['service']}"
                  f"{' ⚠️  RISKY' if result['risky'] else ''}")
            open_ports.append(result)

    return open_ports


def generate_report(target_ip: str, open_ports: list) -> dict:
    risky_ports = [p for p in open_ports if p["risky"]]

    # Count total CVEs found across all ports
    total_cves = sum(p.get("cve_count", 0) for p in open_ports)

    report = {
        "target": target_ip,
        "scan_time": datetime.utcnow().isoformat(),
        "total_open_ports": len(open_ports),
        "risky_ports_found": len(risky_ports),
        "total_cves_found": total_cves,           # NEW
        "risk_level": "HIGH" if risky_ports else "LOW",
        "open_ports": open_ports,
        "risky_ports": risky_ports
    }

    return report


def run_scan(ip, port_range=(1, 1024), lookup_cves=False):
    """Run a full scan and return results with metrics."""
    
    ACTIVE_SCANS.inc()  # increment active scans
    start_time = time.time()
    
    try:
        results = scan_ports(ip, port_range)
        
        if lookup_cves:
            results = enrich_scan_results(results)
        
        report = generate_report(ip, results)
        
        # Record metrics
        SCANS_TOTAL.inc()
        OPEN_PORTS_FOUND.inc(len(results))
        RISKY_PORTS_FOUND.inc(report['risky_ports_found'])
        
        if lookup_cves:
            total_cves = sum(p.get('cve_count', 0) for p in results)
            CVES_FOUND.inc(total_cves)
        
        # Record scan duration
        duration = time.time() - start_time
        SCAN_DURATION.observe(duration)
        
        return report
    
    finally:
        ACTIVE_SCANS.dec()  # decrement active scans when done

def start_metrics_server(port=8000):
    """Start Prometheus metrics HTTP server."""
    start_http_server(port)
    print(f"Metrics server running on port {port}")


# ─────────────────────────────────────────
# Run directly: python src/scanner.py
# ─────────────────────────────────────────
if __name__ == "__main__":
    import os
    
    # Start metrics server so Prometheus can scrape
    start_metrics_server(8000)
    
    target_ip = os.environ.get('TARGET_IP', '127.0.0.1')
    
    print(f"Starting continuous scan of {target_ip}")
    
    # Scan continuously so container stays alive
    # and Prometheus keeps collecting metrics
    while True:
        result = run_scan(target_ip, (1, 1024), lookup_cves=False)
        print(f"Scan complete — {result['total_open_ports']} ports found")
        time.sleep(300)  # scan every 5 minutes