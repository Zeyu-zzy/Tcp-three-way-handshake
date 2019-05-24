# Tcp-three-way-handshake
Implement three-way handshake of TCP with rawsocket on Ubuntu 16.04

```
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
make
sudo ./3way-handshake
```
