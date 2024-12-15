import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import os

# Function to scan a single host
def scan_host(host, timeout=3):
    result = {"host": host, "ip": None, "server": None, "port": None, "status_code": None}
    try:
        # Resolve IP
        ip = socket.gethostbyname(host)
        result["ip"] = ip

        # Check HTTP server
        sock = socket.create_connection((host, 80), timeout)
        result["port"] = 80
        result["server"] = "HTTP"
        result["status_code"] = "Open"
        sock.close()
    except (socket.gaierror, socket.timeout, ConnectionRefusedError):
        pass  # Skip if unreachable or error

    return result

# Function to handle scanning
def scanner(targets, threads):
    working_hosts = []
    total = len(targets)
    current = 0

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_host = {executor.submit(scan_host, host): host for host in targets}

        print("\nScanning hosts...")
        print("-" * 50)

        for future in as_completed(future_to_host):
            current += 1
            result = future.result()
            progress = f"[{'+' * (current % 10)}{'-' * (10 - (current % 10))}]"
            print(f"\r{progress} {current}/{total}", end="")

            if result["ip"]:  # Add only if scan was successful
                working_hosts.append(result)

    print("\n" + "-" * 50)
    return working_hosts

# Main script logic
def main():
    print("Host Finder")
    print("Select scanning mode:")
    print("1. File with hostnames")
    print("2. CIDR range")
    print("3. Single domain")

    choice = input("Enter your choice (1/2/3): ")

    # Input handling based on choice
    targets = []
    if choice == "1":
        filename = input("Enter the file name: ")
        try:
            with open(filename, "r") as file:
                targets = [line.strip() for line in file if line.strip()]
        except FileNotFoundError:
            print("File not found! Exiting.")
            return
    elif choice == "2":
        cidr = input("Enter the CIDR range (e.g., 192.168.1.0/24): ")
        try:
            targets = [str(ip) for ip in ipaddress.IPv4Network(cidr, strict=False)]
        except ValueError:
            print("Invalid CIDR range! Exiting.")
            return
    elif choice == "3":
        domain = input("Enter the domain: ")
        targets = [domain]
    else:
        print("Invalid choice! Exiting.")
        return

    # Ask for number of threads
    try:
        threads = int(input("Enter the number of threads to use: "))
    except ValueError:
        print("Invalid number of threads! Exiting.")
        return

    # Perform scanning
    print("Starting the scan...")
    results = scanner(targets, threads)

    # Display results in a simple table
    print("\nWorking Hosts")
    print("-" * 50)
    print(f"{'Host':<30} {'IP':<15} {'Server':<10} {'Port':<5}")
    print("-" * 50)
    for res in results:
        print(f"{res['host']:<30} {res['ip']:<15} {res['server']:<10} {res['port']:<5}")

    # Save results to file if requested
    if results:
        save = input("Save results to a file? (y/n): ").lower()
        if save == "y":
            filename = input("Enter the file name to save: ")
            with open(filename, "w") as file:
                file.write("Host,IP,Server,Port\n")
                for res in results:
                    file.write(f"{res['host']},{res['ip']},{res['server']},{res['port']}\n")
            print(f"Results saved to {filename}")

if __name__ == "__main__":
    main()
