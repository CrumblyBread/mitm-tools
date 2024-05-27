```text
___  ________ ________  ___     _____ _____  _____ _      _____ 
|  \/  |_   _|_   _|  \/  |    |_   _|  _  ||  _  | |    /  ___|
| .  . | | |   | | | .  . |______| | | | | || | | | |    \ `--. 
| |\/| | | |   | | | |\/| |______| | | | | || | | | |     `--. \
| |  | |_| |_  | | | |  | |      | | \ \_/ /\ \_/ / |____/\__/ /
\_|  |_/\___/  \_/ \_|  |_/      \_/  \___/  \___/\_____/\____/ 
```
# MITM-tools

MITM-tools is a Python application designed to carry out Man-In-The-Middle (MITM) attacks on IPv6 devices. The application is structured into three main modes: MITM Gateway, Rogue DHCPv6 Server, and Rogue DNS Server.

## Features

- **MITM Gateway:** Intercepts and modifies traffic between devices.
- **Rogue DHCPv6 Server:** Acts as a fake DHCPv6 server to assign IP addresses.
- **Rogue DNS Server:** Provides false DNS information to redirect traffic.

## System Requirements

- Operating System: Linux
- Python: Python 3.x
- Additional Dependencies:
  - `python-scapy`
  - `os`
  - `python-threading`
  - `regex`
  - `dhcpAM`
  - `ipaddress`

## Installation

To install MITM-tools, follow these steps:

1. Clone the repository from GitHub:
```bash
git clone https://github.com/yourusername/MITM-tools.git
```

2. Navigate to the project directory:
```bash   
cd MITM-tools
```
3. Install the required dependencies:
```bash  
pip install -r requirements.txt
```

## Usage

Testing was only one on a Linux machine, for this reason it is recommended to not run on Windows, the script might not work properly if it works at all !!

Mitm-tools are made in Python so you will need it to run them.<br>
You can choose one of three modes of to use. The fake gateway mode, the fake DHCPv6 server and the fake DNS server.
You can always use the <mark>--help</mark> option to get more information about what options the program needs.

```console
user@laptop:~$ sudo python mitm.py dns --help
```

#### Example commands

```console
user@laptop:~$ sudo python mitm.py gateway -t fe80::abcd:1 -gw fe80::1 -i eth07
```
```console
user@laptop:~$ sudo python mitm.py dhcp -T targets.txt -fA 9999::1 -lA 9999::ffff -i eth07
```
```console
user@laptop:~$ sudo python mitm.py dns -i eth07 -dns ~/Documents/dns.txt -T targets.txt
```

### Contributing

Contributions are welcome! Please follow these steps to contribute:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes and commit them (`git commit -m 'Add some feature'`).
4. Push to the branch (`git push origin feature-branch`).
5. Open a Pull Request.

## Contact

For support or inquiries, please contact the project maintainer at `branokad33@gmail.com`.
