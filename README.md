```text
___  ________ ________  ___     _____ _____  _____ _      _____ 
|  \/  |_   _|_   _|  \/  |    |_   _|  _  ||  _  | |    /  ___|
| .  . | | |   | | | .  . |______| | | | | || | | | |    \ `--. 
| |\/| | | |   | | | |\/| |______| | | | | || | | | |     `--. \
| |  | |_| |_  | | | |  | |      | | \ \_/ /\ \_/ / |____/\__/ /
\_|  |_/\___/  \_/ \_|  |_/      \_/  \___/  \___/\_____/\____/ 
```
#

Mitm-tools are a set of tools made in Python centered around Man-in-the-middle attacks in IPv6 networks

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
