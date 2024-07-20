import nmap

def scan(host):
    nm = nmap.PortScanner()
    print(f"Scanning {host}...")
    nm.scan(host, '1-1024')  # Сканирование портов от 1 до 1024

    for host in nm.all_hosts():
        print(f"\nHost: {host} ({nm[host].hostname()})")
        print(f"State: {nm[host].state()}")

        for proto in nm[host].all_protocols():
            print(f"\nProtocol: {proto}")

            lport = nm[host][proto].keys()
            for port in sorted(lport):
                print(f"Port: {port}\tState: {nm[host][proto][port]['state']}")

if __name__ == "__main__":
    target = input("Enter the host to scan (e.g., 192.168.1.1): ")
    scan(target)
