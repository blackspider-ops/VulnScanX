from scapy.all import IP, ICMP, sr1, TCP

def icmp_ping_scan(target):
    """Performs an ICMP ping scan to check if the host is alive."""
    packet = IP(dst=target)/ICMP()
    response = sr1(packet, timeout=2, verbose=False)

    if response:
        print(f"[+] Host {target} is up.")
    else:
        print(f"[-] Host {target} is down or not responding.")

def tcp_syn_scan(target, port):
    """Performs a TCP SYN scan on a specific port."""
    packet = IP(dst=target)/TCP(dport=port, flags="S")
    response = sr1(packet, timeout=2, verbose=False)

    if response and response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12:
            print(f"[+] Port {port} on {target} is open.")
        elif response.getlayer(TCP).flags == 0x14:
            print(f"[-] Port {port} on {target} is closed.")
    else:
        print(f"[-] No response from {target}:{port}.")

if __name__ == "__main__":
    target_ip = input("Enter target IP: ")
    icmp_ping_scan(target_ip)
    for port in [22, 80, 443, 445]:  # Scanning common ports
        tcp_syn_scan(target_ip, port)
