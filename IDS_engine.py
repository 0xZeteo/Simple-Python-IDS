from datetime import datetime
import re
import time

# Simulating packet capture
class SimulatedPacket:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol, payload=""):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.payload = payload
        self.timestamp = time.time()

    def __str__(self):
        return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} [{self.protocol}]"

# Sample packets
sample_packets = [
    SimulatedPacket('192.168.1.10', '192.168.1.100', 45678, 80, 'TCP', 'GET /index.html HTTP/1.1'),
    SimulatedPacket('192.168.1.10', '192.168.1.100', 45678, 80, 'TCP', 'GET /about.html HTTP/1.1'),
    SimulatedPacket('192.168.1.20', '192.168.1.100', 12345, 22, 'TCP', 'SSH Connection'),
    SimulatedPacket('192.168.1.40', '192.168.1.100', 45679, 80, 'TCP', "<script>alert('XSS')</script>"),

    # Port scan simulation
    SimulatedPacket("192.168.1.50", "192.168.1.100", 33333, 21, "TCP"),
    SimulatedPacket("192.168.1.50", "192.168.1.100", 33334, 22, "TCP"),
    SimulatedPacket("192.168.1.50", "192.168.1.100", 33335, 23, "TCP"),
    SimulatedPacket("192.168.1.50", "192.168.1.100", 33336, 25, "TCP"),
    SimulatedPacket("192.168.1.50", "192.168.1.100", 33337, 80, "TCP"),
    SimulatedPacket("192.168.1.50", "192.168.1.100", 33338, 443, "TCP"),
]

# IDS Engine
class NetworkIDS:
    def __init__(self):
        self.connections = {}  # src_ip -> list of (dst_ip, dst_port, timestamp)
        self.port_scans = {}   # src_ip -> set of dst_ports
        self.payload_signatures = [
            (r"union\s+select", "SQL Injection"),
            (r"<script>", "XSS Attack"),
            (r"/etc/passwd", "Path Traversal"),
            (r"eval\(", "Code Injection"),
        ]

    def analyze_packet(self, packet):
        alerts = []
        timestamp = datetime.fromtimestamp(packet.timestamp).strftime('%Y-%m-%d %H:%M:%S')

        # Track connections
        if packet.src_ip not in self.connections:
            self.connections[packet.src_ip] = []
        self.connections[packet.src_ip].append((packet.dst_ip, packet.dst_port, packet.timestamp))

        # Track port scans
        if packet.src_ip not in self.port_scans:
            self.port_scans[packet.src_ip] = set()
        self.port_scans[packet.src_ip].add(packet.dst_port)

        # Detect port scanning
        recent_connections = [conn for conn in self.connections[packet.src_ip] if packet.timestamp - conn[2] < 60]
        recent_ports = set(conn[1] for conn in recent_connections)
        if len(recent_ports) >= 5:
            alerts.append(f"[{timestamp}] ALERT: Possible port scan from {packet.src_ip} - {len(recent_ports)} ports in the last minute")

        # Detect payload-based attacks
        if packet.payload:
            for pattern, attack_type in self.payload_signatures:
                if re.search(pattern, packet.payload, re.IGNORECASE):
                    alerts.append(f"[{timestamp}] ALERT: {attack_type} from {packet.src_ip} - Payload: {packet.payload[:50]}...")

        return alerts

    def monitor_network(self, packets):
        for packet in packets:
            print(f"Analyzing packet: {packet}")
            alerts = self.analyze_packet(packet)
            for alert in alerts:
                print(f"\033[91m{alert}\033[0m")
            print("-" * 80)

# Run IDS
network_ids = NetworkIDS()
print("Starting Network IDS...")
print("=" * 80)
network_ids.monitor_network(sample_packets)
print("=" * 80)
print("Network IDS monitoring complete.")
