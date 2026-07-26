"""Simple network scanner: host discovery, port scan, and banner grabbing.

Intended for scanning networks you own or are authorized to test.
"""
import ipaddress
import json
import platform
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

import typer

try:
    from scapy.all import ARP, Ether, srp
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
                445, 993, 995, 1723, 3306, 3389, 5900, 8080]
DEFAULT_PORTS = ",".join(map(str, COMMON_PORTS))

app = typer.Typer(
    add_completion=False,
    help="Host discovery + port scan + banner grab for a local subnet.",
)


def parse_ports(port_str):
    ports = set()
    for part in port_str.split(","):
        if "-" in part:
            lo, hi = part.split("-")
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def arp_scan(cidr, retries=5, timeout=1):
    if not HAVE_SCAPY:
        raise RuntimeError("scapy is required for ARP scanning (pip install 'netscan[arp]')")
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
    answered, _ = srp(packet, timeout=timeout, retry=max(retries - 1, 0), verbose=False)
    return [{"ip": rcv.psrc, "mac": rcv.hwsrc} for _, rcv in answered]


def ping_host(ip, timeout=1):
    if platform.system().lower() == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(int(timeout), 1)), ip]
    try:
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, timeout=timeout + 2)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def ping_sweep(cidr, timeout=1, max_workers=100):
    network = ipaddress.ip_network(cidr, strict=False)
    alive = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(ping_host, str(ip), timeout): str(ip) for ip in network.hosts()}
        for f in as_completed(futures):
            ip = futures[f]
            if f.result():
                alive.append(ip)
    return [{"ip": ip, "mac": None} for ip in alive]


def grab_banner(s, ip, timeout):
    """Read whatever the service sends first (SSH/FTP/SMTP-style banners) on
    an already-connected socket; if it says nothing, probe with an HTTP
    request in case it's a web server waiting to be asked."""
    s.settimeout(timeout)
    try:
        data = s.recv(256)
    except socket.timeout:
        data = b""
    if not data:
        try:
            s.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
            data = s.recv(256)
        except OSError:
            data = b""
    line = data.decode(errors="replace").strip().split("\r\n")[0]
    return line or None


def scan_ports(ip, ports, timeout=1.0, max_workers=100):
    def check(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) != 0:
                    return None
                return (port, grab_banner(s, ip, timeout))
        except OSError:
            return None

    open_ports = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(check, p) for p in ports]
        for f in as_completed(futures):
            r = f.result()
            if r:
                open_ports.append(r)
    return sorted(open_ports)


@app.command(
    epilog="ARP scanning needs root/administrator privileges (and, on native "
           "Windows, Npcap). Use --no-arp to fall back to an ICMP ping sweep "
           "instead, which needs no elevated privileges.",
)
def scan(
    target: str = typer.Argument(..., help="CIDR range to scan, e.g. 192.168.1.0/24"),
    ports: str = typer.Option(DEFAULT_PORTS, help="Ports/ranges, e.g. 1-1000,8080"),
    retries: int = typer.Option(5, help="ARP request retries per host"),
    timeout: float = typer.Option(1.0, help="Per-probe timeout in seconds"),
    threads: int = typer.Option(100, help="Max concurrent worker threads"),
    no_arp: bool = typer.Option(False, "--no-arp", help="Skip ARP discovery, use an ICMP ping sweep instead"),
    json_output: bool = typer.Option(False, "--json", help="Print results as JSON"),
):
    port_list = parse_ports(ports)
    use_arp = HAVE_SCAPY and not no_arp

    typer.echo(f"[*] Discovering live hosts on {target} "
               f"({'ARP' if use_arp else 'ping sweep'}) ...", err=True)

    if use_arp:
        try:
            hosts = arp_scan(target, retries=retries, timeout=timeout)
        except PermissionError:
            typer.echo("[!] ARP scan requires root/administrator privileges "
                       "(try: sudo netscan ...)", err=True)
            raise typer.Exit(code=1)
    else:
        if not HAVE_SCAPY and not no_arp:
            typer.echo("[!] scapy not installed, falling back to ping sweep "
                       "(pip install 'netscan[arp]' for ARP discovery)", err=True)
        hosts = ping_sweep(target, timeout=timeout, max_workers=threads)

    if not hosts:
        typer.echo("[!] No live hosts found.")
        raise typer.Exit()

    hosts.sort(key=lambda h: ipaddress.ip_address(h["ip"]))
    typer.echo(f"[+] Found {len(hosts)} live host(s)\n")

    results = []
    for host in hosts:
        ip, mac = host["ip"], host.get("mac")
        typer.echo(f"Host: {ip}" + (f"  (MAC: {mac})" if mac else ""))
        open_ports = scan_ports(ip, port_list, timeout=timeout, max_workers=threads)
        entry = {"ip": ip, "mac": mac, "ports": []}
        if not open_ports:
            typer.echo("  no open ports found")
        for port, banner in open_ports:
            line = f"  {port}/tcp open"
            if banner:
                line += f"  {banner}"
            typer.echo(line)
            entry["ports"].append({"port": port, "banner": banner})
        results.append(entry)
        typer.echo("")

    if json_output:
        typer.echo(json.dumps(results, indent=2))


def main():
    app()


if __name__ == "__main__":
    main()
