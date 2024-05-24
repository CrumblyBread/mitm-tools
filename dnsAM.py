import scapy.all
from scapy.all import DNS,DNSRR
from scapy.ansmachine import AnsweringMachine
from scapy.base_classes import Net
from scapy.config import conf
from scapy.compat import orb, raw, chb, bytes_encode, plain_str
from scapy.error import log_runtime, warning, Scapy_Exception
from scapy.packet import Packet, bind_layers, Raw
from scapy.fields import (
    BitEnumField,
    BitField,
    ByteEnumField,
    ByteField,
    ConditionalField,
    Field,
    FieldLenField,
    FieldListField,
    FlagsField,
    I,
    IP6Field,
    IntField,
    MultipleTypeField,
    PacketListField,
    ShortEnumField,
    ShortField,
    StrField,
    StrLenField,
    UTCTimeField,
    XStrFixedLenField,
    XStrLenField,
)
from scapy.sendrecv import sr1
from scapy.supersocket import StreamSocket
from scapy.pton_ntop import inet_ntop, inet_pton
from scapy.volatile import RandShort

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, DestIPField, IPField, UDP, TCP

class DNS_am(AnsweringMachine):
    function_name = "dnsd"
    filter = "udp port 53"
    cls = DNS  # We also use this automaton for llmnrd / mdnsd

    def parse_options(self, joker=None,
                      match=None,
                      srvmatch=None,
                      joker6=False,
                      send_error=False,
                      relay=False,
                      from_ip=None,
                      from_ip6=None,
                      src_ip=None,
                      src_ip6=None,
                      ttl=10,
                      jokerarpa=None):
        """
        :param joker: default IPv4 for unresolved domains. (Default: None)
                      Set to False to disable, None to mirror the interface's IP.
        :param joker6: default IPv6 for unresolved domains (Default: False)
                       set to False to disable, None to mirror the interface's IPv6.
        :param jokerarpa: answer for .in-addr.arpa PTR requests. (Default: None)
        :param relay: relay unresolved domains to conf.nameservers (Default: False).
        :param send_error: send an error message when this server can't answer
                           (Default: False)
        :param match: a dictionary of {name: val} where name is a string representing
                      a domain name (A, AAAA) and val is a tuple of 2 elements, each
                      representing an IP or a list of IPs. If val is a single element,
                      (A, None) is assumed.
        :param srvmatch: a dictionary of {name: (port, target)} used for SRV
        :param from_ip: an source IP to filter. Can contain a netmask
        :param from_ip6: an source IPv6 to filter. Can contain a netmask
        :param ttl: the DNS time to live (in seconds)
        :param src_ip: override the source IP
        :param src_ip6:

        Example::

            $ sudo iptables -I OUTPUT -p icmp --icmp-type 3/3 -j DROP
            >>> dnsd(match={"google.com": "1.1.1.1"}, joker="192.168.0.2", iface="eth0")
            >>> dnsd(srvmatch={
            ...     "_ldap._tcp.dc._msdcs.DOMAIN.LOCAL.": (389, "srv1.domain.local")
            ... })
        """
        def normv(v):
            if isinstance(v, (tuple, list)) and len(v) == 2:
                return v
            elif isinstance(v, str):
                return (v, None)
            else:
                raise ValueError("Bad match value: '%s'" % repr(v))

        def normk(k):
            k = bytes_encode(k).lower()
            if not k.endswith(b"."):
                k += b"."
            return k
        if match is None:
            self.match = {}
        else:
            self.match = {normk(k): normv(v) for k, v in match.items()}
        if srvmatch is None:
            self.srvmatch = {}
        else:
            self.srvmatch = {normk(k): normv(v) for k, v in srvmatch.items()}
        self.joker = joker
        self.joker6 = joker6
        self.jokerarpa = jokerarpa
        self.send_error = send_error
        self.relay = relay
        if isinstance(from_ip, str):
            self.from_ip = Net(from_ip)
        else:
            self.from_ip = from_ip
        if isinstance(from_ip6, str):
            self.from_ip6 = Net(from_ip6)
        else:
            self.from_ip6 = from_ip6
        self.src_ip = src_ip
        self.src_ip6 = src_ip6
        self.ttl = ttl

    def is_request(self, req):
        from scapy.layers.inet6 import IPv6
        return (
            req.haslayer(self.cls) and
            req.getlayer(self.cls).qr == 0 and (
                (
                    not self.from_ip6 or req[IPv6].src in self.from_ip6
                )
                if IPv6 in req else
                (
                    not self.from_ip or req[IP].src in self.from_ip
                )
            )
        )

    def make_reply(self, req):
        print("1")
        mDNS = isinstance(self, mDNS_am)
        llmnr = self.cls != DNS
        # Build reply from the request
        resp = req.copy()
        if Ether in req:
            if mDNS:
                resp[Ether].src, resp[Ether].dst = None, None
            elif llmnr:
                resp[Ether].src, resp[Ether].dst = None, req[Ether].src
            else:
                resp[Ether].src, resp[Ether].dst = (
                    None if req[Ether].dst in "ff:ff:ff:ff:ff:ff" else req[Ether].dst,
                    req[Ether].src,
                )
        from scapy.layers.inet6 import IPv6
        if IPv6 in req:
            resp[IPv6].underlayer.remove_payload()
            if mDNS:
                resp /= IPv6(dst="ff02::fb", src=self.src_ip6)
            elif llmnr:
                resp /= IPv6(dst=req[IPv6].src, src=self.src_ip6)
            else:
                resp /= IPv6(dst=req[IPv6].src, src=self.src_ip6 or req[IPv6].dst)
        elif IP in req:
            resp[IP].underlayer.remove_payload()
            if mDNS:
                resp /= IP(dst="224.0.0.251", src=self.src_ip)
            elif llmnr:
                resp /= IP(dst=req[IP].src, src=self.src_ip)
            else:
                resp /= IP(dst=req[IP].src, src=self.src_ip or req[IP].dst)
        else:
            print("2")
            warning("No IP or IPv6 layer in %s", req.command())
            return
        try:
            resp /= UDP(sport=req[UDP].dport, dport=req[UDP].sport)
        except IndexError:
            print("3")
            warning("No UDP layer in %s", req.command(), exc_info=True)
            return
        # Now process each query and store its answer in 'ans'
        ans = []
        try:
            req = req[self.cls]
        except IndexError:
            warning(
                "No %s layer in %s",
                self.cls.__name__,
                req.command(),
                exc_info=True,
            )
            print("4")
            return
        try:
            queries = req.qd
        except AttributeError:
            warning("No qd attribute in %s", req.command(), exc_info=True)
            return
        for rq in queries:
            # For each query
            if isinstance(rq, Raw):
                warning("Cannot parse qd element %s", rq.command(), exc_info=True)
                continue
            if rq.qtype in [1, 28]:
                # A or AAAA
                if rq.qtype == 28:
                    # AAAA
                    try:
                        rdata = self.match[rq.qname.lower()][1]
                    except KeyError:
                        if self.relay or self.joker6 is False:
                            rdata = None
                        else:
                            rdata = self.joker6 or get_if_addr6(
                                self.optsniff.get("iface", conf.iface)
                            )
                elif rq.qtype == 1:
                    # A
                    try:
                        rdata = self.match[rq.qname.lower()][0]
                    except KeyError:
                        if self.relay or self.joker is False:
                            rdata = None
                        else:
                            rdata = self.joker or get_if_addr(
                                self.optsniff.get("iface", conf.iface)
                            )
                if rdata is not None:
                    # Common A and AAAA
                    if not isinstance(rdata, list):
                        rdata = [rdata]
                    ans.extend([
                        DNSRR(rrname=rq.qname, ttl=self.ttl, rdata=x, type=rq.qtype)
                        for x in rdata
                    ])
                    continue  # next
            elif rq.qtype == 33:
                # SRV
                try:
                    port, target = self.srvmatch[rq.qname.lower()]
                    ans.append(DNSRRSRV(
                        rrname=rq.qname,
                        port=port,
                        target=target,
                        weight=100,
                        ttl=self.ttl
                    ))
                    continue  # next
                except KeyError:
                    # No result
                    pass
            elif rq.qtype == 12:
                # PTR
                if rq.qname[-14:] == b".in-addr.arpa." and self.jokerarpa:
                    ans.append(DNSRR(
                        rrname=rq.qname,
                        type=rq.qtype,
                        ttl=self.ttl,
                        rdata=self.jokerarpa,
                    ))
                    continue
            # It it arrives here, there is currently no answer
            if self.relay:
                # Relay mode ?
                try:
                    _rslv = dns_resolve(rq.qname, qtype=rq.qtype)
                    if _rslv:
                        ans.extend(_rslv)
                        continue  # next
                except TimeoutError:
                    pass
            # Error
            break
        else:
            if not ans:
                # No rq was actually answered, as none was valid. Discard.
                print("5")
                return
            # All rq were answered
            if mDNS:
                # in mDNS mode, don't repeat the question
                resp /= self.cls(id=req.id, qr=1, qd=[], an=ans)
            else:
                resp /= self.cls(id=req.id, qr=1, qd=req.qd, an=ans)
            print("6")
            return resp
        # An error happened
        if self.send_error:
            resp /= self.cls(id=req.id, qr=1, qd=req.qd, rcode=3)
            print("7")
            return resp


class mDNS_am(DNS_am):
    """
    mDNS answering machine.

    This has the same arguments as DNS_am. See help(DNS_am)

    Example::

        >>> mdnsd(joker="192.168.0.2", iface="eth0")
        >>> mdnsd(match={"TEST.local": "192.168.0.2"})
    """
    function_name = "mdnsd"
    filter = "udp port 5353"