import socket
import time
import ssl
import json
from honeypot_detector import detect_honeypot
from utils import save_log

def scan_port(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    start_time = time.time()
    try:
        result = s.connect_ex((ip, port))
        response_time = round((time.time() - start_time) * 1000, 3)
        if result != 0:
            return None
        banner = "Unknown Service"
        if port in [443, 8443, 9443, 8010]:
            try:
                context = ssl._create_unverified_context()
                ssl_sock = context.wrap_socket(s, server_hostname=ip)
                cert = ssl_sock.getpeercert()
                cn = "Unknown"
                issuer = "Unknown"
                try:
                    for item in cert.get("subject", []):
                        d = dict(item)
                        if "commonName" in d:
                            cn = d["commonName"]
                except:
                    pass
                try:
                    for item in cert.get("issuer", []):
                        d = dict(item)
                        if "organizationName" in d:
                            issuer = d["organizationName"]
                except:
                    pass
                banner = f"HTTPS Service | CN={cn} | Issuer={issuer}"
                ssl_sock.close()

                return {
                    "port": port,
                    "status": "open",
                    "response_time_ms": response_time,
                    "banner": banner
                }
            except Exception as e:
                banner = f"TLS handshake failed ({e})"
        try:
            s.send(b"HEAD / HTTP/1.1\r\nHost: test\r\n\r\n")
            data = s.recv(1024).decode(errors="ignore")
            if "HTTP/" in data:
                banner = data.split("\n")[0].strip()
        except:
            pass
        return {
            "port": port,
            "status": "open",
            "response_time_ms": response_time,
            "banner": banner
        }
    except:
        return None
    finally:
        try: s.close()
        except: pass
def scan_range(ip, start_port, end_port):
    results = []
    print(f"\nScanning {ip} ...\n")
    for port in range(start_port, end_port + 1):
        r = scan_port(ip, port)
        if r:
            print(f"[+] Port {port} OPEN  |  Banner: {r['banner']}")
            results.append(r)
    hp = detect_honeypot(results)
    print("\nHoneypot Analysis:", hp)
    final_output = {"target": ip, "open_ports": results, "honeypot_suspected": hp}
    save_log(final_output)
    return final_output

if __name__ == "__main__":
    ip = input("Enter IP to scan: ")
    start = int(input("Start port: "))
    end = int(input("End port: "))
    scan_range(ip, start, end)
