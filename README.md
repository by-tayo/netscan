# netscan

A small CLI for scanning your own local network: it finds live hosts on a
subnet, checks which TCP ports are open on each one, and grabs a banner from
anything it can, so you get a quick "what's alive and what's it running"
picture of your LAN.

Only scan networks you own or are explicitly authorized to test.

## What it does

1. **Host discovery** — finds live IPs on a subnet, either via:
   - ARP requests (fast, gets MAC addresses; needs `scapy` and root/admin), or
   - an ICMP ping sweep (no elevated privileges needed; used automatically if
     `scapy` isn't installed, or via `--no-arp`)
2. **Port scan** — multithreaded TCP connect scan over a configurable port
   list (defaults to ~20 common ports).
3. **Banner grab** — reads whatever a service announces first (SSH/FTP/SMTP
   style banners), or probes it with an HTTP request if it stays silent.

## Install

```bash
python3 -m venv .venv
source .venv/Scripts/activate   # or .venv/bin/activate on Linux/WSL
pip install -e .
```

For ARP-based discovery, install the optional `scapy` dependency too:

```bash
pip install -e '.[arp]'
```

On native Windows, ARP scanning also requires [Npcap](https://npcap.com/).
The ping-sweep fallback works everywhere with no extra setup.

## Usage

```bash
netscan 192.168.1.0/24                       # full scan, ARP if available
netscan 192.168.1.0/24 --no-arp              # force ping-sweep discovery
netscan 192.168.1.0/24 --ports 1-1000,8080   # custom port range
netscan 192.168.1.0/24 --json                # machine-readable output
sudo netscan 192.168.1.0/24 --retries 5       # ARP scan needs root on Linux/WSL
```

### Options

| Option       | Default          | Description                                   |
|--------------|------------------|------------------------------------------------|
| `--ports`    | common ports     | Ports/ranges to scan, e.g. `1-1000,8080`        |
| `--retries`  | `5`              | ARP request retries per host                    |
| `--timeout`  | `1.0`            | Per-probe timeout in seconds                    |
| `--threads`  | `100`            | Max concurrent worker threads                   |
| `--no-arp`   | off              | Skip ARP discovery, use an ICMP ping sweep      |
| `--json`     | off              | Print results as JSON instead of plain text     |

Run `netscan --help` for the full reference.
