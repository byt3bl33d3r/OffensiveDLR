# Kukulkan Payload Server

```bash
usage: server.py [-h] [-d] <bindip> <port> [--password PASSWORD]

arguments:
  bindip    port to bind to
  port      port to bind to

options:
  -h, --help   show this screen
  -d, --debug  show debug output
  -p, --password PASSWORD  stage and job zip file password [default: kukulkan]
```


## Example

```bash
python server.py -d 172.16.164.1 8080
```
