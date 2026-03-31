from scapy.all import sniff, IP, TCP, UDP
import time
import requests
import queue
import threading

API_URL = "http://127.0.0.1:8000/analyze"
packet_queue = queue.Queue()

def packet_callback(packet):
    if IP in packet:
        # Extract arbitrary features for the prototype mock
        # In a real scenario, this would compute flow duration, packet sizes, flags, etc.
        length = len(packet)
        ttl = packet[IP].ttl
        proto = packet[IP].proto
        
        # Map to our 4-feature mock space
        feature_vector = [float((length % 10) / 10), float(ttl / 255.0), float(proto / 10.0), 0.5]
        packet_queue.put(feature_vector)

def process_queue():
    sequence = []
    while True:
        feature = packet_queue.get()
        sequence.append(feature)
        
        if len(sequence) >= 5:
            # We need sequences of length 5 as requested by LSTM
            sample = feature
            payload = {
                "sample": sample,
                "sequence": sequence[-5:]
            }
            try:
                # Send to API
                response = requests.post(API_URL, json=payload)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('action') in ['BLOCK', 'ALERT']:
                        print(f"[{data.get('action')}] Threat Detected: {data.get('label')} (Conf: {data.get('confidence'):.2f})")
                        if data.get('action') == 'BLOCK':
                            print("System would apply firewall block rule here.")
            except requests.exceptions.ConnectionError:
                # API might not be running
                pass
            
            # Slide window
            sequence.pop(0)

def simulate_traffic():
    import random
    print("Generating simulated network traffic for demonstration...")
    while True:
        length = random.randint(40, 1500)
        ttl = random.randint(50, 64)
        proto = random.choice([6, 17]) # TCP or UDP
        feature_vector = [float((length % 10) / 10), float(ttl / 255.0), float(proto / 10.0), 0.5]
        
        # Introduce some anomalies randomly to trigger alerts/blocks
        if random.random() < 0.2:
            feature_vector[3] = 1.0
            feature_vector[0] = 0.9 
            
        packet_queue.put(feature_vector)
        time.sleep(1) # Send 1 packet per second

if __name__ == "__main__":
    print("Starting EchoTrace-AutoShield live network sniffer...")
    # Start processor thread
    t = threading.Thread(target=process_queue, daemon=True)
    t.start()
    
    # Start sniffing
    print("Capturing packets... (Make sure API is running! Press Ctrl+C to stop)")
    try:
        # Using filter="ip" to only catch IP packets
        sniff(filter="ip", prn=packet_callback, store=0)
    except Exception as e:
        print(f"\n[!] Real network sniffing unavailable: {e}")
        print("[!] This usually means 'Npcap' is not installed or you lack Administrator privileges.")
        print("[*] Falling back to Simulated Network Traffic Mode...\n")
        simulate_traffic()
