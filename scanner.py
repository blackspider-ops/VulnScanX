import nmap
import json

def load_vulnerabilities():
    with open("vuln_db.json", "r") as file:
        return json.load(file)


def scan_network(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-sS -p 1-1000')
    vuln_db = load_vulnerabilities()

    for host in nm.all_hosts():
        print(f"\nHost: {host} ({nm[host].hostname()})")
        print(f"State: {nm[host].state()}")

        for proto in nm[host].all_protocols():
            print(f"Protocol: {proto}")
            ports = nm[host][proto].keys()
            for port in ports:
                state = nm[host][proto][port]['state']
                print(f"Port: {port}\tState: {state}")

                if str(port) in vuln_db:
                    vuln = vuln_db[str(port)]
                    print(f"⚠️  Vulnerability found: {vuln['service']} - {vuln['cve']} (Risk: {vuln['risk']})")

if __name__ == "__main__":
    target_ip = input("Enter target IP or range (e.g., 192.168.1.0/24): ")
    scan_network(target_ip)
