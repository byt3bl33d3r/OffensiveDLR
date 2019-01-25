# Kukulkan Payload Server

```bash
usage: server.py [-h] [-d] [--regen-cert] <bindip> <port>

arguments:
  bindip    port to bind to
  port      port to bind to

options:
  -h, --help    show this screen
  -d, --debug   show debug output
  --regen-cert  regenerate TLS certificate
```


## Example

```bash
python server.py 172.16.164.1 8080
```
