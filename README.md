# Tcp-three-way-handshake
Implement three-way handshake of TCP with rawsocket on Linux

```
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
make
sudo ./3way-handshake
```