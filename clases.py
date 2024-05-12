from scapy.all import PcapWriter
from datetime import date

class Device:
    def __init__(self, linklocal = "", globalip = "", macaddr = ""):
        self.linklocal = linklocal
        self.globalip = globalip
        self.macaddr = macaddr

class vPort(Device):
    def __init__(self, linklocal = "", globalip = "", macaddr = ""):
        self.linklocal = linklocal
        self.globalip = globalip
        self.macaddr = macaddr

    def AddTarget(self,target,write):
        self.targetDevice = target
        self.write = write
        if write:
            self.pcap = PcapWriter(f"{self.targetDevice.linklocal}.pcap",append=True,sync=True)
    def Write(self,packet):
        if not self.write:
            return
        self.pcap.write(packet)