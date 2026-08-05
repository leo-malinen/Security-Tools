import random
import time

SUSPECT = ["185.203.116.7", "45.155.205.233", "91.240.118.172"]
NORMAL = ["10.0.0.15", "10.0.0.22", "192.168.1.44", "192.168.1.90"]
TARGET = "10.0.0.5"


def seed_normal_traffic(storage, minutes=20, per_minute=40):
    now = time.time()
    packets = []
    for minute in range(minutes, 0, -1):
        base = now - minute * 60
        for _ in range(per_minute):
            packets.append(
                {
                    "ts": base + random.random() * 60,
                    "src_ip": random.choice(NORMAL),
                    "dst_ip": TARGET,
                    "src_port": random.randint(30000, 60000),
                    "dst_port": random.choice([80, 443, 53, 8080]),
                    "protocol": "TCP",
                    "length": random.randint(200, 1400),
                    "flags": "PSH|ACK",
                }
            )
    storage.add_packets(packets)
    return len(packets)


def seed_port_scan(storage, ip=None, ports=80):
    src = ip or SUSPECT[0]
    now = time.time()
    packets = [
        {
            "ts": now - random.random() * 30,
            "src_ip": src,
            "dst_ip": TARGET,
            "src_port": random.randint(40000, 60000),
            "dst_port": port,
            "protocol": "TCP",
            "length": 60,
            "flags": "SYN",
        }
        for port in range(1, ports + 1)
    ]
    storage.add_packets(packets)
    return src


def seed_brute_force(storage, ip=None, attempts=40):
    src = ip or SUSPECT[1]
    now = time.time()
    for index in range(attempts):
        storage.add_auth_event(
            {
                "ts": now - index * 3,
                "src_ip": src,
                "username": random.choice(["root", "admin", "ubuntu", "test"]),
                "service": "sshd",
                "port": 22,
                "success": False,
            }
        )
    return src


def seed_traffic_spike(storage, ip=None, packets=4000):
    src = ip or SUSPECT[2]
    now = time.time()
    burst = [
        {
            "ts": now - random.random() * 30,
            "src_ip": src,
            "dst_ip": TARGET,
            "src_port": random.randint(1024, 65535),
            "dst_port": 443,
            "protocol": "UDP",
            "length": random.randint(800, 1500),
            "flags": None,
        }
        for _ in range(packets)
    ]
    storage.add_packets(burst)
    return src


def seed_blocklist(storage):
    storage.replace_blocklist([(ip, "simulated-feed") for ip in SUSPECT])
    return SUSPECT


def seed_all(storage):
    seed_normal_traffic(storage)
    seed_port_scan(storage)
    seed_brute_force(storage)
    seed_traffic_spike(storage)
    seed_blocklist(storage)
