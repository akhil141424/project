from scapy.all import sniff, IP, TCP, UDP, conf
import datetime
import sys

# Import the Brain we just built
try:
    from brain import engine
except ImportError:
    print("Error: Could not import 'engine' from brain.py. Make sure both files are in the same folder.")
    sys.exit(1)

LOG_FILE = "logs/alerts.log"

def extract_features(packet):
    """
    Turns a raw packet into a list of 10 numbers (features) for the AI.
    Features: [Proto, Len, TTL, Sport, Dport, TCP_Flags, Window, ...placeholders...]
    """
    try:
        # We only care about IP packets
        if IP not in packet:
            return None, None, None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        length = len(packet)
        ttl = packet[IP].ttl
        
        sport = 0
        dport = 0
        flags = 0
        window = 0

        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = int(packet[TCP].flags)
            window = packet[TCP].window
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        
        # Normalize features (divide by max values) to help the AI model
        features = [
            proto / 255.0,           # 1. Protocol
            min(length, 1500)/1500,  # 2. Length (cap at 1500)
            ttl / 255.0,             # 3. TTL
            sport / 65535.0,         # 4. Source Port
            dport / 65535.0,         # 5. Dest Port
            flags / 255.0,           # 6. TCP Flags
            window / 65535.0,        # 7. Window Size
            0.5, 0.5, 0.5            # 8,9,10. Placeholders for other metrics
        ]
        
        return features, src_ip, dst_ip

    except Exception as e:
        # Packet might be malformed or non-standard
        return None, None, None

def packet_callback(packet):
    """Called for every single packet captured."""
    features, src, dst = extract_features(packet)
    
    if features:
        # Ask the Hybrid Brain: "Is this an attack?"
        is_threat, severity, method = engine.detect(features)
        
        if is_threat:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # 1. Print to Terminal (so you see it working)
            print(f"[{timestamp}] 🚨 ALERT: {method} | {src} -> {dst}")
            
            # 2. Save to Log File (for the Dashboard)
            with open(LOG_FILE, "a") as f:
                # Format: Time,Source,Destination,Severity,Method
                f.write(f"{timestamp},{src},{dst},{severity},{method}\n")

if __name__ == "__main__":
    print(">> Aegis-IDS Sensor Starting...")
    print(f">> Logging alerts to: {LOG_FILE}")
    
    # Optional: Force Scapy to use a specific interface if auto-detection fails
    # conf.iface = "Wi-Fi" 
    
    print(">> Sniffing traffic... (Press Ctrl+C to stop)")
    
    try:
        # store=0 is crucial! It means "don't keep packets in RAM", otherwise PC crashes.
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\n>> Stopping Sniffer.")
    except Exception as e:
        print(f"\n!! Error: {e}")
        print("Try running VS Code as Administrator.")