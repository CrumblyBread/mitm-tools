from scapy.all import PcapWriter
from datetime import date

class Device:
    def __init__(self, linklocal = "", globalip = "", macaddr = ""):
        self.linklocal = linklocal
        self.globalip = globalip
        self.macaddr = macaddr

class vPort(Device):
    def AddTarget(self,target,write):
        self.targetDevice = target
        self.pcap = PcapWriter(f"{self.linklocal}",append=True,sync=True)
        self.write = write
    def Write(self,packet):
        if not self.write:
            return
        self.pcap.write(packet)