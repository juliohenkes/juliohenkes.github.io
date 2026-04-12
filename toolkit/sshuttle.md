---
title: "sshuttle"
---

# sshuttle

Pivoting via sshuttle over a reverse SSH tunnel. The compromised host creates a reverse SSH tunnel back to Kali, which uses sshuttle to transparently route all traffic destined for the internal network as if it were a VPN.

```shell
# On the pivot — create reverse SSH tunnel to Kali (port 3000)
ssh <user_pivot2>@<ip_pivot1> -p 3000

# On Kali — transparent routing via sshuttle
sshuttle -r <user_pivot2>@<ip_vps_pivot1>:3000 <target_network3> --disable-ipv6
```
