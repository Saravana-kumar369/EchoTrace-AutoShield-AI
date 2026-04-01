"""
Live network sniffer for EchoTrace-AutoShield.
Captures real packets (or simulates traffic) and sends to the AI engine.
Updated for NSL-KDD 122-feature model.
"""
from scapy.all import sniff, IP, TCP, UDP
import time
import requests
import queue
import threading
import numpy as np

API_URL = "http://127.0.0.1:8000/analyze"
packet_queue = queue.Queue()

# NSL-KDD has 122 features after one-hot encoding.
# We extract what we can from raw packets and zero-pad the rest.
# The model's scaler will normalize everything.
NUM_FEATURES = 122

def extract_features(packet):
    """Extract NSL-KDD-compatible features from a raw packet."""
    features = np.zeros(NUM_FEATURES, dtype=np.float32)
    
    if IP in packet:
        # Basic features (indices match NSL-KDD column order)
        features[0] = 0  # duration (unknown for single packet)
        features[4] = len(packet)  # src_bytes approximation
        features[5] = 0  # dst_bytes
        features[6] = 1 if packet[IP].ttl == 0 else 0  # land
        features[7] = 0  # wrong_fragment
        features[8] = 0  # urgent
        
        # Connection features
        features[22] = 1  # count
        features[23] = 1  # srv_count
        
        # Protocol one-hot (these indices depend on encoding order)
        if TCP in packet:
            features[38] = 1  # protocol_type_tcp (approximate index)
            if packet[TCP].flags:
                flags = packet[TCP].flags
                features[24] = 1 if flags & 0x04 else 0  # serror (RST)
                features[26] = 1 if flags & 0x04 else 0  # rerror
        elif UDP in packet:
            features[39] = 1  # protocol_type_udp
        else:
            features[40] = 1  # protocol_type_icmp
    
    return features.tolist()

def packet_callback(packet):
    if IP in packet:
        features = extract_features(packet)
        packet_queue.put(features)

def process_queue():
    sequence = []
    while True:
        feature = packet_queue.get()
        sequence.append(feature)
        
        if len(sequence) >= 5:
            payload = {
                "sample": feature,
                "sequence": sequence[-5:]
            }
            try:
                response = requests.post(API_URL, json=payload, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    action = data.get('action', 'PASS')
                    if action in ['BLOCK', 'ALERT']:
                        label = data.get('label', '?')
                        conf = data.get('confidence', 0)
                        print(f"[{action}] {label} detected ({conf*100:.1f}% confidence)")
            except requests.exceptions.ConnectionError:
                pass
            except Exception:
                pass
            
            sequence.pop(0)

def simulate_traffic():
    """Generate simulated traffic with occasional attack patterns."""
    import random
    print("Generating simulated network traffic...")
    while True:
        features = np.zeros(NUM_FEATURES, dtype=np.float32)
        features[4] = random.randint(40, 1500)  # src_bytes
        features[22] = random.randint(1, 10)  # count
        features[23] = random.randint(1, 5)  # srv_count
        features[38] = 1  # TCP
        
        # 20% chance of anomalous traffic
        if random.random() < 0.2:
            features[4] = random.randint(5000, 50000)  # high bytes
            features[22] = random.randint(100, 500)  # high connection count
            features[24] = random.uniform(0.5, 1.0)  # high serror_rate
        
        packet_queue.put(features.tolist())
        time.sleep(1)

if __name__ == "__main__":
    print("EchoTrace-AutoShield Network Sniffer")
    print(f"Features: {NUM_FEATURES} (NSL-KDD compatible)")
    print(f"API: {API_URL}")
    print("-" * 40)
    
    t = threading.Thread(target=process_queue, daemon=True)
    t.start()
    
    try:
        sniff(filter="ip", prn=packet_callback, store=0)
    except Exception as e:
        print(f"Real sniffing unavailable: {e}")
        print("Falling back to simulated traffic...\n")
        simulate_traffic()
