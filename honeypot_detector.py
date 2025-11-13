def detect_honeypot(open_ports):
    if not open_ports:
        return "No open ports detected (likely not a honeypot)"
    banners = [p["banner"].lower() for p in open_ports]
    times = [p["response_time_ms"] for p in open_ports]
    clues = []
    for b in banners:
        if "ssh-2.0-kippo" in b or "cowrie" in b:
            clues.append("Cowrie/Kippo Honeypot signature detected")
    if len(open_ports) > 25:
        clues.append("Unusual amount of open ports — possible Portspoof")
    avg = sum(times) / len(times)
    if avg > 300:
        clues.append("Consistent high-latency responses — suspicious")
    if len(set(banners)) == 1 and len(banners) > 3:
        clues.append("Same banner on all ports — fake service generation")
    if len(clues) == 0:
        return "No honeypot behavior detected"
    return f"Possible Honeypot: {', '.join(clues)}"
