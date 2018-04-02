# Hilldust
(UNOFFICIAL) Yet another implementation of *Hillstone™ Secure Connect VPN Client* for Linux

and for macOS later.

## Usage
```
./hilldust.py vpn.yourdomain.com:12345 username password
```
As `vpn.yourdomain.com:12345` is your VPN provider's address.

## Notes
For now, it is only a proof-of-concept and may be not available for all the users,
because it only supports auth: `HMAC-SHA1-96`, crypto: `3DES-CBC`.

## Dependencies
- Python 3
- scapy (Python module)
- cryptography (Python module)
- iproute2

Please note different systems may have different names for Python 3.
It can be: `python3` with `pip3`, or `python` with `pip`,

You may use the shortcut: `pip3 install -r requirements.txt` to install all
Python modules the program needs.

You may use `ip -Version` to check if your system is missing iproute2 utility.
