import scapy.all as scapy
import time

# Function to load a PCAP file
def load_pcap(file_path):
    try:
        packets = scapy.rdpcap(file_path)
        return packets
    except FileNotFoundError:
        print("PCAP file not found. Please check the file path.")
        return []

# Function to detect SYN Flood attack
def detect_syn_flood(packets, threshold=100):
    syn_packets = []

    for packet in packets:
        if scapy.IP in packet and scapy.TCP in packet:
            if packet[scapy.TCP].flags == 'S':
                syn_packets.append(packet)

    if len(syn_packets) > threshold:
        return syn_packets
    else:
        return None

# Function to analyze detected packets
def analyze_packets(packets):
    if packets:
        print("Possible SYN Flood Attack Detected!")
        print("Detected SYN Packets:")
        for packet in packets:
            print(packet.summary())
        print(f"Attack Timestamp: {time.ctime()}")
    else:
        print("No signs of a SYN Flood attack found.")

# Function to log attack details to a file
def log_attack_details(packets):
    if packets:
        with open("attack_log.txt", "a") as log_file:
            log_file.write("Possible SYN Flood Attack Detected!\n")
            log_file.write("Detected SYN Packets:\n")
            for packet in packets:
                log_file.write(packet.summary() + "\n")
            log_file.write(f"Attack Timestamp: {time.ctime()}\n")
            log_file.write("\n")

# Main function
def main():
    print("Simple DoS Attack Detector")

    file_path = input("Enter the path to the PCAP file: ")
    packets = load_pcap(file_path)

    if not packets:
        print("No packets found in the PCAP file. Exiting.")
        return

    syn_flood_packets = detect_syn_flood(packets)
    analyze_packets(syn_flood_packets)
    log_attack_details(syn_flood_packets)

if __name__ == "__main__":
    main()