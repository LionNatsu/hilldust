# Hilldust
(UNOFFICIAL) Yet another implementation of Hillstone™ Secure Connect VPN Client for Linux

## Usage
```
./client.py vpn.yourdomain.com:12345 username password
```
As `vpn.yourdomain.com:12345` is your VPN provider's address.

## Notes
For now, it is only a proof-of-concept and not really available, because:

- it has no TUN/TAP binding, work-in-progress
- it only supports auth: `HMAC-SHA1-96`, crypto: `3DES-CBC`.

## Dependencies
- Python 3
- scapy (Python Module)
