import time
import warnings

from scapy.ansmachine import AnsweringMachine
from scapy.arch import get_if_raw_hwaddr, in6_getifaddr
from scapy.config import conf
from scapy.data import EPOCH
from scapy.compat import raw, orb
from scapy.error import warning
from scapy.layers.inet import UDP
from scapy.themes import Color
from scapy.utils6 import in6_addrtovendor, in6_islladdr
from scapy.all import IPv6,DHCP6OptDNSServers, DHCP6OptDNSDomains, DHCP6OptSNTPServers, DHCP6OptSIPServers, DHCP6OptSIPDomains, DHCP6OptNISServers,DHCP6OptNISDomain, DHCP6OptNISPServers, DHCP6OptNISPDomain, DHCP6OptBCMCSServers, DHCP6OptBCMCSDomains, DUID_LLT, DHCP6, DHCP6OptClientId, DHCP6OptServerId, DHCP6OptIA_NA, DHCP6OptIA_TA, DHCP6OptIAAddress, DHCP6OptIA_PD,DHCP6OptOptReq,DHCP6OptRapidCommit, DHCP6_Reply, DHCP6_Advertise, DHCP6OptStatusCode, DHCP6OptPref, DHCP6OptReconfAccept, DHCP6_Solicit

class DHCPv6_am(AnsweringMachine):
    function_name = "dhcp6d"
    filter = "udp and port 546 and port 547"

    def usage(self):
        msg = """
DHCPv6_am.parse_options( dns="2001:500::1035", domain="localdomain, local",
        duid=None, iface=conf.iface, advpref=255, sntpservers=None,
        sipdomains=None, sipservers=None,
        nisdomain=None, nisservers=None,
        nispdomain=None, nispservers=None,
        bcmcsdomains=None, bcmcsservers=None)

   debug : When set, additional debugging information is printed.

   duid   : some DUID class (DUID_LLT, DUID_LL or DUID_EN). If none
            is provided a DUID_LLT is constructed based on the MAC
            address of the sending interface and launch time of dhcp6d
            answering machine.

   iface : the interface to listen/reply on if you do not want to use
           conf.iface.

   advpref : Value in [0,255] given to Advertise preference field.
             By default, 255 is used. Be aware that this specific
             value makes clients stops waiting for further Advertise
             messages from other servers.

   dns : list of recursive DNS servers addresses (as a string or list).
         By default, it is set empty and the associated DHCP6OptDNSServers
         option is inactive. See RFC 3646 for details.
   domain : a list of DNS search domain (as a string or list). By default,
         it is empty and the associated DHCP6OptDomains option is inactive.
         See RFC 3646 for details.

   sntpservers : a list of SNTP servers IPv6 addresses. By default,
         it is empty and the associated DHCP6OptSNTPServers option
         is inactive.

   sipdomains : a list of SIP domains. By default, it is empty and the
         associated DHCP6OptSIPDomains option is inactive. See RFC 3319
         for details.
   sipservers : a list of SIP servers IPv6 addresses. By default, it is
         empty and the associated DHCP6OptSIPDomains option is inactive.
         See RFC 3319 for details.

   nisdomain : a list of NIS domains. By default, it is empty and the
         associated DHCP6OptNISDomains option is inactive. See RFC 3898
         for details. See RFC 3646 for details.
   nisservers : a list of NIS servers IPv6 addresses. By default, it is
         empty and the associated DHCP6OptNISServers option is inactive.
         See RFC 3646 for details.

   nispdomain : a list of NIS+ domains. By default, it is empty and the
         associated DHCP6OptNISPDomains option is inactive. See RFC 3898
         for details.
   nispservers : a list of NIS+ servers IPv6 addresses. By default, it is
         empty and the associated DHCP6OptNISServers option is inactive.
         See RFC 3898 for details.

   bcmcsdomain : a list of BCMCS domains. By default, it is empty and the
         associated DHCP6OptBCMCSDomains option is inactive. See RFC 4280
         for details.
   bcmcsservers : a list of BCMCS servers IPv6 addresses. By default, it is
         empty and the associated DHCP6OptBCMCSServers option is inactive.
         See RFC 4280 for details.

   If you have a need for others, just ask ... or provide a patch."""
        print(msg)

    def parse_options(self, dns="2001:500::1035", domain="localdomain, local",
                      startip="2001:db8::1", endip="2001:db8::20", duid=None,
                      sntpservers=None, sipdomains=None, sipservers=None,
                      nisdomain=None, nisservers=None, nispdomain=None,
                      nispservers=None, bcmcsservers=None, bcmcsdomains=None,
                      iface=None, debug=0, advpref=255):
        def norm_list(val, param_name):
            if val is None:
                return None
            if isinstance(val, list):
                return val
            elif isinstance(val, str):
                tmp_len = val.split(',')
                return [x.strip() for x in tmp_len]
            else:
                print("Bad '%s' parameter provided." % param_name)
                self.usage()
                return -1

        if iface is None:
            iface = conf.iface

        self.debug = debug
        self.dns = dns

        # Dictionary of provided DHCPv6 options, keyed by option type
        self.dhcpv6_options = {}

        for o in [(dns, "dns", 23, lambda x: DHCP6OptDNSServers(dnsservers=x)),
                  (domain, "domain", 24, lambda x: DHCP6OptDNSDomains(dnsdomains=x)),  # noqa: E501
                  (sntpservers, "sntpservers", 31, lambda x: DHCP6OptSNTPServers(sntpservers=x)),  # noqa: E501
                  (sipservers, "sipservers", 22, lambda x: DHCP6OptSIPServers(sipservers=x)),  # noqa: E501
                  (sipdomains, "sipdomains", 21, lambda x: DHCP6OptSIPDomains(sipdomains=x)),  # noqa: E501
                  (nisservers, "nisservers", 27, lambda x: DHCP6OptNISServers(nisservers=x)),  # noqa: E501
                  (nisdomain, "nisdomain", 29, lambda x: DHCP6OptNISDomain(nisdomain=(x + [""])[0])),  # noqa: E501
                  (nispservers, "nispservers", 28, lambda x: DHCP6OptNISPServers(nispservers=x)),  # noqa: E501
                  (nispdomain, "nispdomain", 30, lambda x: DHCP6OptNISPDomain(nispdomain=(x + [""])[0])),  # noqa: E501
                  (bcmcsservers, "bcmcsservers", 33, lambda x: DHCP6OptBCMCSServers(bcmcsservers=x)),  # noqa: E501
                  (bcmcsdomains, "bcmcsdomains", 34, lambda x: DHCP6OptBCMCSDomains(bcmcsdomains=x))]:  # noqa: E501

            opt = norm_list(o[0], o[1])
            if opt == -1:  # Usage() was triggered
                return False
            elif opt is None:  # We won't return that option
                pass
            else:
                self.dhcpv6_options[o[2]] = o[3](opt)

        if self.debug:
            print("\n[+] List of active DHCPv6 options:")
            opts = sorted(self.dhcpv6_options)
            for i in opts:
                print("    %d: %s" % (i, repr(self.dhcpv6_options[i])))

        # Preference value used in Advertise.
        self.advpref = advpref

        # IP Pool
        self.startip = startip
        self.endip = endip
        # XXX TODO Check IPs are in same subnet
        self.lastip = ipaddress.ip_address(startip) - 1

        ####
        # The interface we are listening/replying on
        self.iface = iface

        ####
        # Generate a server DUID
        if duid is not None:
            self.duid = duid
        else:
            # Timeval
            epoch = (2000, 1, 1, 0, 0, 0, 5, 1, 0)
            delta = time.mktime(epoch) - EPOCH
            timeval = time.time() - delta

            # Mac Address
            rawmac = get_if_raw_hwaddr(iface)[1]
            mac = ":".join("%.02x" % orb(x) for x in rawmac)

            self.duid = DUID_LLT(timeval=timeval, lladdr=mac)

        if self.debug:
            print("\n[+] Our server DUID:")
            self.duid.show(label_lvl=" " * 4)

        ####
        # Find the source address we will use
        self.src_addr = None
        try:
            addr = next(x for x in in6_getifaddr() if x[2] == iface and in6_islladdr(x[0]))  # noqa: E501
        except (StopIteration, RuntimeError):
            warning("Unable to get a Link-Local address")
            return
        else:
            self.src_addr = addr[0]

        ####
        # Our leases
        self.leases = {}

        if self.debug:
            print("\n[+] Starting DHCPv6 service on %s:" % self.iface)

    def is_request(self, p):
        if IPv6 not in p:
            return False

        src = p[IPv6].src

        p = p[IPv6].payload
        if not isinstance(p, UDP) or p.sport != 546 or p.dport != 547:
            return False

        p = p.payload
        if not isinstance(p, DHCP6):
            return False

        # Message we considered client messages :
        # Solicit (1), Request (3), Confirm (4), Renew (5), Rebind (6)
        # Decline (9), Release (8), Information-request (11),
        if not (p.msgtype in [1, 3, 4, 5, 6, 8, 9, 11]):
            return False

        # Message validation following section 15 of RFC 3315

        if ((p.msgtype == 1) or  # Solicit
            (p.msgtype == 6) or  # Rebind
                (p.msgtype == 4)):  # Confirm
            if ((DHCP6OptClientId not in p) or
                    DHCP6OptServerId in p):
                return False

            if (p.msgtype == 6 or  # Rebind
                    p.msgtype == 4):  # Confirm
                # XXX We do not reply to Confirm or Rebind as we
                # XXX do not support address assignment
                return False

        elif (p.msgtype == 3 or  # Request
              p.msgtype == 5 or  # Renew
              p.msgtype == 8):  # Release

            # Both options must be present
            if ((DHCP6OptServerId not in p) or
                    (DHCP6OptClientId not in p)):
                return False
            # provided server DUID must match ours
            duid = p[DHCP6OptServerId].duid
            if not isinstance(duid, type(self.duid)):
                return False
            if raw(duid) != raw(self.duid):
                return False

            if (p.msgtype == 5 or  # Renew
                    p.msgtype == 8):  # Release
                # XXX We do not reply to Renew or Release as we
                # XXX do not support address assignment
                return False

        elif p.msgtype == 9:  # Decline
            # XXX We should check if we are tracking that client
            if not self.debug:
                return False

            bo = Color.bold
            g = Color.green + bo
            b = Color.blue + bo
            n = Color.normal
            r = Color.red

            vendor = in6_addrtovendor(src)
            if (vendor and vendor != "UNKNOWN"):
                vendor = " [" + b + vendor + n + "]"
            else:
                vendor = ""
            src = bo + src + n

            it = p
            addrs = []
            while it:
                lst = []
                if isinstance(it, DHCP6OptIA_NA):
                    lst = it.ianaopts
                elif isinstance(it, DHCP6OptIA_TA):
                    lst = it.iataopts

                addrs += [x.addr for x in lst if isinstance(x, DHCP6OptIAAddress)]  # noqa: E501
                it = it.payload

            addrs = [bo + x + n for x in addrs]
            if self.debug:
                msg = r + "[DEBUG]" + n + " Received " + g + "Decline" + n
                msg += " from " + bo + src + vendor + " for "
                msg += ", ".join(addrs) + n
                print(msg)

            # See RFC 3315 sect 18.1.7

            # Sent by a client to warn us she has determined
            # one or more addresses assigned to her is already
            # used on the link.
            # We should simply log that fact. No messaged should
            # be sent in return.

            # - Message must include a Server identifier option
            # - the content of the Server identifier option must
            #   match the server's identifier
            # - the message must include a Client Identifier option
            return False

        elif p.msgtype == 11:  # Information-Request
            if DHCP6OptServerId in p:
                duid = p[DHCP6OptServerId].duid
                if not isinstance(duid, type(self.duid)):
                    return False
                if raw(duid) != raw(self.duid):
                    return False
            if ((DHCP6OptIA_NA in p) or
                (DHCP6OptIA_TA in p) or
                    (DHCP6OptIA_PD in p)):
                return False
        else:
            return False

        return True

    def get_next_addr(self):
        if self.lastip == self.endip or self.endip == ipaddress.ip_address(self.lastip) + 1:
            return -1
        else:
            self.lastip = ipaddress.ip_address(self.lastip) + 1
            return self.lastip

    def print_reply(self, req, reply):
        def norm(s):
            if s.startswith("DHCPv6 "):
                s = s[7:]
            if s.endswith(" Message"):
                s = s[:-8]
            return s

        if reply is None:
            return

        bo = Color.bold
        g = Color.green + bo
        b = Color.blue + bo
        n = Color.normal
        reqtype = g + norm(req.getlayer(UDP).payload.name) + n
        reqsrc = req.getlayer(IPv6).src
        vendor = in6_addrtovendor(reqsrc)
        if (vendor and vendor != "UNKNOWN"):
            vendor = " [" + b + vendor + n + "]"
        else:
            vendor = ""
        reqsrc = bo + reqsrc + n
        reptype = g + norm(reply.getlayer(UDP).payload.name) + n

        print("Sent %s answering to %s from %s%s" % (reptype, reqtype, reqsrc, vendor))  # noqa: E501

    def make_reply(self, req):
        p = req[IPv6]
        req_src = p.src

        p = p.payload.payload

        msgtype = p.msgtype
        trid = p.trid

        def _include_options(query, answer):
            """
            Include options from the DHCPv6 query
            """

            # See which options should be included
            reqopts = []
            if query.haslayer(DHCP6OptOptReq):  # add only asked ones
                reqopts = query[DHCP6OptOptReq].reqopts
                for o, opt in self.dhcpv6_options.items():
                    if o in reqopts:
                        answer /= opt
            else:
                warnings.warn("Wrong request options")
                # advertise everything we have available
                # Should not happen has clients MUST include
                # and ORO in requests (sec 18.1.1)   -- arno
                for o, opt in self.dhcpv6_options.items():
                    answer /= opt

        if msgtype == 1:  # SOLICIT (See Sect 17.1 and 17.2 of RFC 3315)

            client_duid = p[DHCP6OptClientId].duid
            resp = IPv6(src=self.src_addr, dst=req_src)
            resp /= UDP(sport=547, dport=546)

            if p.haslayer(DHCP6OptRapidCommit):
                # construct a Reply packet
                resp /= DHCP6_Reply(trid=trid)
                resp /= DHCP6OptRapidCommit()  # See 17.1.2
                resp /= DHCP6OptServerId(duid=self.duid)
                resp /= DHCP6OptClientId(duid=client_duid)

            else:  # No Rapid Commit in the packet. Reply with an Advertise

                if p.haslayer(DHCP6OptIA_NA):
                    addr = self.get_next_addr()
                    if addr == -1:
                        msg = "All addresses in pool depleted :("
                        resp /= DHCP6_Advertise(trid=trid)
                        resp /= DHCP6OptStatusCode(statuscode=6, statusmsg=msg)
                        resp /= DHCP6OptServerId(duid=self.duid)
                        resp /= DHCP6OptClientId(duid=client_duid)
                        return resp

                    resp /= DHCP6_Advertise(trid=trid)
                    resp /= DHCP6OptServerId(duid=self.duid)
                    resp /= DHCP6OptClientId(duid=client_duid)
                    resp /= DHCP6OptIA_NA(ianaopts=[DHCP6OptIAAddress(preflft=300, validlft=300, addr=addr)], T1=200, T2=250, iaid=p[DHCP6OptIA_NA].iaid)
                    _include_options(p, resp)
                    
                elif p.haslayer(DHCP6OptIA_TA):
                    pass

                elif p.haslayer(DHCP6OptIA_PD):
                    # XXX We don't assign prefixes at the moment
                    msg = "Scapy6 dhcp6d does not support prefix assignment"
                    resp /= DHCP6_Advertise(trid=trid)
                    resp /= DHCP6OptStatusCode(statuscode=0, statusmsg=msg)
                    resp /= DHCP6OptServerId(duid=self.duid)
                    resp /= DHCP6OptClientId(duid=client_duid)
                    _include_options(p, resp)


                else:  # Usual case, no request for prefixes or addresse
                    resp /= DHCP6_Advertise(trid=trid)
                    resp /= DHCP6OptPref(prefval=self.advpref)
                    resp /= DHCP6OptServerId(duid=self.duid)
                    resp /= DHCP6OptClientId(duid=client_duid)
                    resp /= DHCP6OptReconfAccept()
                    _include_options(p, resp)

            return resp

        elif msgtype == 3:  # REQUEST (INFO-REQUEST is further below)
            client_duid = p[DHCP6OptClientId].duid
            resp = IPv6(src=self.src_addr, dst=req_src)
            resp /= UDP(sport=547, dport=546)
            resp /= DHCP6_Reply(trid=trid)
            resp /= DHCP6OptServerId(duid=self.duid)
            resp /= DHCP6OptClientId(duid=client_duid)
            resp /= DHCP6OptIA_NA(ianaopts=p[DHCP6OptIAAddress], T1=200, T2=250, iaid=p[DHCP6OptIA_NA].iaid)

            _include_options(p, resp)

            return resp

        elif msgtype == 4:  # CONFIRM
            # see Sect 18.1.2

            # Client want to check if addresses it was assigned
            # are still appropriate

            # Server must discard any Confirm messages that
            # do not include a Client Identifier option OR
            # THAT DO INCLUDE a Server Identifier Option

            # XXX we must discard the SOLICIT if it is received with
            #     a unicast destination address

            pass

        elif msgtype == 5:  # RENEW
            # see Sect 18.1.3

            # Clients want to extend lifetime of assigned addresses
            # and update configuration parameters. This message is sent
            # specifically to the server that provided her the info

            # - Received message must include a Server Identifier
            #   option.
            # - the content of server identifier option must match
            #   the server's identifier.
            # - the message must include a Client identifier option

            pass

        elif msgtype == 6:  # REBIND
            # see Sect 18.1.4

            # Same purpose as the Renew message but sent to any
            # available server after he received no response
            # to its previous Renew message.

            # - Message must include a Client Identifier Option
            # - Message can't include a Server identifier option

            # XXX we must discard the SOLICIT if it is received with
            #     a unicast destination address

            pass

        elif msgtype == 8:  # RELEASE
            # See RFC 3315 section 18.1.6

            # Message is sent to the server to indicate that
            # she will no longer use the addresses that was assigned
            # We should parse the message and verify our dictionary
            # to log that fact.

            # - The message must include a server identifier option
            # - The content of the Server Identifier option must
            #   match the server's identifier
            # - the message must include a Client Identifier option

            pass

        elif msgtype == 9:  # DECLINE
            # See RFC 3315 section 18.1.7
            pass

        elif msgtype == 11:  # INFO-REQUEST
            client_duid = None
            if not p.haslayer(DHCP6OptClientId):
                if self.debug:
                    warning("Received Info Request message without Client Id option")  # noqa: E501
            else:
                client_duid = p[DHCP6OptClientId].duid

            resp = IPv6(src=self.src_addr, dst=req_src)
            resp /= UDP(sport=547, dport=546)
            resp /= DHCP6_Reply(trid=trid)
            resp /= DHCP6OptServerId(duid=self.duid)

            if client_duid:
                resp /= DHCP6OptClientId(duid=client_duid)

            # Stack requested options if available
            for o, opt in self.dhcpv6_options.items():
                resp /= opt

            return resp

        else:
            # what else ?
            pass

        # - We won't support reemission
        # - We won't support relay role, nor relay forwarded messages
        #   at the beginning