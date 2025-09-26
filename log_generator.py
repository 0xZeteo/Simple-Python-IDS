#!/usr/bin/env python3
"""
log_generator.py
Part 2 — Generate synthetic network logs for IDS practicals.

Usage examples:
# Generate 200 events into logs.jsonl at roughly 20 events/sec
python log_generator.py --count 200 --rate 20 --out logs.jsonl

# Run continuously (until Ctrl+C) producing ~5 events/sec
python log_generator.py --rate 5 --out logs.jsonl --continuous
"""

import argparse
import json
import random
import sys
import time
from datetime import datetime, timezone

# ---- Configurable pools of values ----
COMMON_PATHS = ["/", "/index.html", "/about.html", "/login", "/search?q=test"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "curl/7.68.0",
    "Wget/1.20.3 (linux-gnu)",
    "Python-urllib/3.10",
]
NORMAL_PAYLOADS = [
    "GET /index.html HTTP/1.1",
    "GET /about.html HTTP/1.1",
    "POST /login HTTP/1.1 (username=alice)",
    "SSH Connection",
]

MALICIOUS_PAYLOADS = {
    "xss": "<script>alert('XSS')</script>",
    "sqli": "id=1 OR 1=1 UNION SELECT username,password FROM users",
    "path_traversal": "../etc/passwd",
    "code_injection": "eval('some_malicious_code()')",
}

# Port ranges
COMMON_PORTS = [80, 443, 22, 21, 23, 25, 3306]
HIGH_PORT_RANGE = (1024, 65535)

# Helper to random IPv4
def rand_ipv4(private=True):
    if private:
        # choose one of common private subnets
        subnets = [
            ("192.168.1.", 2, 250),
            ("10.0.0.", 2, 250),
            ("172.16.0.", 2, 250),
        ]
        base, a_min, a_max = random.choice(subnets)
        return base + str(random.randint(a_min, a_max))
    else:
        return ".".join(str(random.randint(1, 254)) for _ in range(4))

# Build a single event dict
def make_event(event_type="normal", src_ip=None, dst_ip=None):
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    src_ip = src_ip or rand_ipv4()
    dst_ip = dst_ip or "192.168.1.100"

    if event_type == "normal":
        payload = random.choice(NORMAL_PAYLOADS)
        src_port = random.randint(*HIGH_PORT_RANGE)
        dst_port = random.choice(COMMON_PORTS)
        protocol = "TCP"
        label = "normal"
    elif event_type == "port_scan":
        # for a port_scan event we represent single probe; generator will create many probes
        payload = ""
        src_port = random.randint(*HIGH_PORT_RANGE)
        dst_port = random.choice(COMMON_PORTS + list(range(1024, 1035)))
        protocol = "TCP"
        label = "port_scan_probe"
    elif event_type == "xss":
        payload = MALICIOUS_PAYLOADS["xss"]
        src_port = random.randint(*HIGH_PORT_RANGE)
        dst_port = 80
        protocol = "HTTP"
        label = "xss"
    elif event_type == "sqli":
        payload = MALICIOUS_PAYLOADS["sqli"]
        src_port = random.randint(*HIGH_PORT_RANGE)
        dst_port = 80
        protocol = "HTTP"
        label = "sqli"
    elif event_type == "path_traversal":
        payload = MALICIOUS_PAYLOADS["path_traversal"]
        src_port = random.randint(*HIGH_PORT_RANGE)
        dst_port = 80
        protocol = "HTTP"
        label = "path_traversal"
    elif event_type == "telnet":
        payload = "Telnet attempt"
        src_port = random.randint(*HIGH_PORT_RANGE)
        dst_port = 23
        protocol = "TCP"
        label = "telnet"
    else:
        # fallback to normal
        payload = random.choice(NORMAL_PAYLOADS)
        src_port = random.randint(*HIGH_PORT_RANGE)
        dst_port = random.choice(COMMON_PORTS)
        protocol = "TCP"
        label = "normal"

    event = {
        "timestamp": now,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "payload": payload,
        "user_agent": random.choice(USER_AGENTS),
        "label": label,
    }
    return event

# Generate a short set of port-scan probes from one source
def emit_port_scan_probes(src_ip, dst_ip, start_port=20, count=8):
    probes = []
    # emit probes across contiguous ports (or picked ports)
    ports = list(range(start_port, start_port + count))
    random.shuffle(ports)
    for p in ports:
        probes.append(make_event("port_scan", src_ip=src_ip, dst_ip=dst_ip))
        probes[-1]["dst_port"] = p
    return probes

# CLI and main loop
def parse_args():
    p = argparse.ArgumentParser(description="Synthetic network log generator for IDS practicals.")
    p.add_argument("--count", "-c", type=int, default=100, help="Number of events to generate (ignored if --continuous).")
    p.add_argument("--rate", "-r", type=float, default=10.0, help="Approx events per second.")
    p.add_argument("--out", "-o", type=str, default="logs.jsonl", help="Output file (JSON Lines).")
    p.add_argument("--continuous", action="store_true", help="Run until interrupted, producing events continuously.")
    p.add_argument("--seed", type=int, default=None, help="Random seed for reproducibility.")
    return p.parse_args()

def main():
    args = parse_args()
    if args.seed is not None:
        random.seed(args.seed)

    out_file = args.out
    rate = max(args.rate, 0.1)
    sleep_time = 1.0 / rate

    print(f"Starting log generator -> {out_file} (rate: {rate} ev/s). Ctrl+C to stop.")
    try:
        written = 0
        with open(out_file, "a", encoding="utf-8") as fh:
            while True:
                # Decide what kind of event to create
                roll = random.random()
                if roll < 0.70:
                    event = make_event("normal")
                elif roll < 0.85:
                    # occasional single malicious payload
                    event = make_event(random.choice(["xss", "sqli", "path_traversal", "telnet"]))
                else:
                    # burst of port scan from one attacker
                    attacker = rand_ipv4(private=False)
                    probes = emit_port_scan_probes(attacker, "192.168.1.100", start_port=random.randint(20, 500))
                    # write the probes with small spacing
                    for probe in probes:
                        line = json.dumps(probe)
                        fh.write(line + "\n")
                        fh.flush()
                        print(format_line(probe))
                        written += 1
                        time.sleep(max(0.01, sleep_time / 3.0))
                    # continue to the next loop iteration
                    if not args.continuous and written >= args.count:
                        break
                    continue

                # normal or single malicious event write
                line = json.dumps(event)
                fh.write(line + "\n")
                fh.flush()
                print(format_line(event))
                written += 1

                if not args.continuous and written >= args.count:
                    break
                time.sleep(sleep_time)

    except KeyboardInterrupt:
        print("\nInterrupted by user — shutting down.")
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
    finally:
        print(f"Total events written: {written}")

def format_line(event):
    # human readable one-line summary (also useful if viewing stdout)
    ts = event["timestamp"]
    s = f"{ts} | {event['src_ip']}:{event['src_port']} -> {event['dst_ip']}:{event['dst_port']} [{event['protocol']}] {event['label']}"
    if event["payload"]:
        s += f" | payload={event['payload'][:60]}{'...' if len(event['payload'])>60 else ''}"
    return s

if __name__ == "__main__":
    main()
