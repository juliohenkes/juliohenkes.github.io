---
title: "History Cleanup"
---

# History Cleanup

Clears bash command history to remove traces of post-exploitation activity.

```shell
set +o history; history -c; history
```
