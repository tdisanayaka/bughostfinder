#!/usr/bin/env python
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn
from rich.table import Table
import os

# Initialize console for colorful output
console = Console()

# Function to scan HTTP
def scan_http(host, timeout=3):
    try:
        response = requests.get(f"http://{host}", timeout=timeout)
        return {
            "host": host,
            "ip": socket.gethostbyname(host),
            "server": response.headers.get("server", "Unknown"),
            "port": 80,
            "status_code": response.status_code,
        }
    except Exception:
        return None

# Function to scan SSL
def scan_ssl(host, timeout=3):
    try:
        response = requests.get(f"http://{host}", timeout=timeout)
        return {
            "host": host,
            "ip": socket.gethostbyname(host),
            "server": response.headers.get("server", "Unknown"),
            "port": 443,
            "status_code": response.status_code,
        }
    except Exception:
        return None

# Function to scan WebSocket (WS)
def scan_ws(host, timeout=3):
    try:
        response = requests.get(f"ws://{host}", timeout=timeout)
        return {
            "host": host,
            "ip": socket.gethostbyname(host),
            "server": response.headers.get("server", "Unknown"),
            "port": 80,
            "status_code": response.status_code,
        }
    except Exception:
        return None

# Function to scan UDP
def scan_udp(host, timeout=3):
    try:
        ip = socket.gethostbyname(host)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(b"ping", (ip, 53))  # Example: Check DNS on port 53
            sock.recvfrom(1024)
            return {"host": host, "ip": ip, "port": 53, "server": "UDP", "status_code": "UDP OK"}
    except Exception:
        return None

# Scanner function that handles the selected protocol
def scanner(targets, protocol, threads, timeout=3):
    protocol_scanners = {
        "http": scan_http,
        "ssl": scan_ssl,
        "ws": scan_ws,
        "udp": scan_udp,
    }

    working_hosts = []
    scanner_function = protocol_scanners.get(protocol)

    if not scanner_function:
        console.print("[bold red]Invalid protocol selected. Exiting.[/bold red]")
        return []

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        "[progress.percentage]{task.percentage:>7.6f}%",
        console=console,
    ) as progress:
        task = progress.add_task("Scanning hosts...", total=len(targets))

        with ThreadPoolExecutor(max_workers=threads) as executor:
            batch_size = 10000  # Process hosts in chunks for large CIDR ranges
            for i in range(0, len(targets), batch_size):
                batch = targets[i:i + batch_size]
                future_to_host = {executor.submit(scanner_function, host, timeout): host for host in batch}

                for future in as_completed(future_to_host):
                    progress.update(task, advance=1)
                    result = future.result()
                    if result:  # Add only if scan was successful
                        working_hosts.append(result)
                        console.print(
                            f"[bold green]Found: {result['host']} ({result['ip']}) | Port: {result['port']} | Status: {result['status_code']}[/bold green]"
                        )

    return working_hosts

# Main script logic
def main():
    console.print("[bold cyan]Welcome to the Host Scanner[/bold cyan]")
    console.print("Select scanning mode:")
    console.print("[1] File with hostnames")
    console.print("[2] CIDR range")
    console.print("[3] Single domain")

    choice = console.input("[bold yellow]Enter your choice (1/2/3): [/bold yellow]")

    # Input handling based on choice
    targets = []
    if choice == "1":
        filename = console.input("[bold yellow]Enter the file name: [/bold yellow]")
        try:
            with open(filename, "r") as file:
                targets = [line.strip() for line in file if line.strip()]
        except FileNotFoundError:
            console.print("[bold red]File not found! Exiting.[/bold red]")
            return
    elif choice == "2":
        cidr = console.input("[bold yellow]Enter the CIDR range (e.g., 192.168.1.0/24): [/bold yellow]")
        try:
            # Process CIDR range incrementally for memory efficiency
            targets = [str(ip) for ip in ipaddress.IPv4Network(cidr, strict=False).hosts()]
        except ValueError:
            console.print("[bold red]Invalid CIDR range! Exiting.[/bold red]")
            return
    elif choice == "3":
        domain = console.input("[bold yellow]Enter the domain: [/bold yellow]")
        targets = [domain]
    else:
        console.print("[bold red]Invalid choice! Exiting.[/bold red]")
        return

    # Ask for the protocol to scan
    console.print("[bold cyan]Select protocol to scan:[/bold cyan]")
    console.print("[1] HTTP")
    console.print("[2] SSL")
    console.print("[3] WebSocket (WS)")
    console.print("[4] UDP")

    protocol_choice = console.input("[bold yellow]Enter your choice (1/2/3/4): [/bold yellow]")
    protocol_map = {"1": "http", "2": "ssl", "3": "ws", "4": "udp"}
    protocol = protocol_map.get(protocol_choice)

    if not protocol:
        console.print("[bold red]Invalid protocol selected! Exiting.[/bold red]")
        return

    # Ask for number of threads
    threads = int(console.input("[bold yellow]Enter the number of threads to use: [/bold yellow]"))

    # Perform scanning
    console.print(f"[bold cyan]Starting the {protocol.upper()} scan...[/bold cyan]")
    results = scanner(targets, protocol, threads)

    # Clear screen before showing the final results
    os.system("cls" if os.name == "nt" else "clear")

    # Display results in a table
    table = Table(title=f"Working Hosts ({protocol.upper()})")
    table.add_column("Host", style="cyan", no_wrap=True)
    table.add_column("IP", style="green")
    table.add_column("Server", style="magenta")
    table.add_column("Port", style="yellow")
    table.add_column("Status Code", style="blue")

    for res in results:
        table.add_row(
            res["host"],
            res["ip"],
            res["server"] or "N/A",
            str(res["port"] or "N/A"),
            str(res["status_code"] or "N/A"),
        )

    console.print(table)

    # Save results to file if requested
    if results:
        save = console.input("[bold yellow]Save results to a file? (y/n): [/bold yellow]").lower()
        if save == "y":
            filename = console.input("[bold yellow]Enter the file name to save: [/bold yellow]")
            with open(filename, "w") as file:
                file.write("Host,IP,Server,Port,Status Code\n")
                for res in results:
                    file.write(
                        f"{res['host']},{res['ip']},{res['server']},{res['port']},{res['status_code']}\n"
                    )
            console.print(f"[bold green]Results saved to {filename}[/bold green]")

if __name__ == "__main__":
    main()
