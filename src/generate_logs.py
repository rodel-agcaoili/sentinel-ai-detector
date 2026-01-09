import pandas as pd
import numpy as np
import random
import time
from datetime import datetime, timedelta

def generate_vpc_flow_logs(num_records=1000, anomaly_ratio=0.05):
    """
    Generates synthetic AWS VPC Flow Logs with injected anomalies.
    """
    data = []
    start_time = int(time.time()) - (num_records * 60)
    
    # Common ports and protocols
    normal_ports = [80, 443, 22, 3306, 5432]
    protocols = [6, 17]  # TCP, UDP
    
    print(f"Generating {num_records} log entries...")

    for i in range(num_records):
        # Base normal behavior
        is_anomaly = random.random() < anomaly_ratio
        
        src_ip = f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
        dst_ip = f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
        src_port = random.randint(1024, 65535)
        dst_port = random.choice(normal_ports)
        protocol = 6
        packets = random.randint(1, 50)
        bytes_transferred = packets * random.randint(40, 1500)
        action = "ACCEPT"
        
        # Inject Specific Anomaly Types
        if is_anomaly:
            anomaly_type = random.choice(['exfiltration', 'port_scan', 'brute_force'])
            
            if anomaly_type == 'exfiltration':
                # Huge byte transfer on unusual port
                dst_port = random.randint(40000, 50000)
                bytes_transferred = random.randint(5000000, 10000000)
                action = "ACCEPT"
            elif anomaly_type == 'port_scan':
                # High packet count, rejected
                dst_port = random.randint(1, 1024)
                action = "REJECT"
                packets = random.randint(100, 500)
            elif anomaly_type == 'brute_force':
                # Constant attempts on port 22
                dst_port = 22
                action = "REJECT"
                packets = 1

        record = {
            'version': 2,
            'account-id': '123456789012',
            'interface-id': 'eni-0af123456789abcde',
            'srcaddr': src_ip,
            'dstaddr': dst_ip,
            'srcport': src_port,
            'dstport': dst_port,
            'protocol': protocol,
            'packets': packets,
            'bytes': bytes_transferred,
            'start': start_time + (i * 60),
            'end': start_time + (i * 60) + 30,
            'action': action,
            'log-status': 'OK',
            'label': 1 if is_anomaly else 0  # 1 for Anomaly, 0 for Normal
        }
        data.append(record)

    df = pd.DataFrame(data)
    df.to_csv('data/synthetic_vpc_logs.csv', index=False)
    print("Successfully saved to data/synthetic_vpc_logs.csv")

if __name__ == "__main__":
    generate_vpc_flow_logs(5000)