import random
import socket
import time
from time import time as t
from dnslib import QTYPE, DNSRecord
from dnslib.server import BaseResolver, DNSServer

class DNS:

    def __init__(self):
        super().__init__()
        self.root_servers = {
            "a.root-servers.net": ("198.41.0.4", "2001:503:ba3e::2:30", "Verisign, Inc."),
            "b.root-servers.net": ("170.247.170.2", "2801:1b8:10::b", "University of Southern California, ISI"),
            "c.root-servers.net": ("192.33.4.12", "2001:500:2::c", "Cogent Communications"),
            "d.root-servers.net": ("199.7.91.13", "2001:500:2d::d", "University of Maryland"),
            "e.root-servers.net": ("192.203.230.10", "2001:500:a8::e", "NASA (Ames Research Center)"),
            "f.root-servers.net": ("192.5.5.241", "2001:500:2f::f", "Internet Systems Consortium, Inc."),
            "g.root-servers.net": ("192.112.36.4", "2001:500:12::d0d", "US Department of Defense (NIC)"),
            "h.root-servers.net": ("198.97.190.53", "2001:500:1::53", "US Army (Research Lab)"),
            "i.root-servers.net": ("192.36.148.17", "2001:7fe::53", "Netnod"),
            "j.root-servers.net": ("192.58.128.30", "2001:503:c27::2:30", "Verisign, Inc."),
            "k.root-servers.net": ("193.0.14.129", "2001:7fd::1", "RIPE NCC"),
            "l.root-servers.net": ("199.7.83.42", "2001:500:9f::42", "ICANN"),
            "m.root-servers.net": ("202.12.27.33", "2001:dc3::35", "WIDE Project"),
        }

        self.ttl_cache = {} 

    def query(self, domain, qtype, server_ip, timeout=2):
        question = DNSRecord.question(domain, qtype)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(question.pack(), (server_ip, 53))
            response_data, _ = sock.recvfrom(512)
            response = DNSRecord.parse(response_data)
            return response
        except:
            return None
        finally:
            sock.close()


    def query_root_servers(self, domain, qtype):
        root_server_names = list(self.root_servers.keys())
        random.shuffle(root_server_names)
        for server_name in root_server_names:
            server_ip = self.root_servers[server_name][0]
            response = self.query(domain, qtype, server_ip)
            if response:
                return response
        return None
    
    def cache_control(self,domain, qtype):
        if self.ttl_cache.get(domain):
            response, ttl, expiry_time = self.ttl_cache[domain]
            if t() < expiry_time:
                return response
            else:
                del self.ttl_cache[domain]
                return None

    
    def search(self, domain, qtype):
        cached = self.cache_control(domain, qtype)
        if cached:
            print(f"Cache hit for {domain} with type {qtype}")
            return cached
        else:
            print(f"Cache miss for {domain} with type {qtype}")
        response = self.query_root_servers(domain, qtype)
        while response and not response.rr:
            if response.ar:
                for r in response.ar:
                    if QTYPE[r.rtype] == "A":
                        next_ip = str(r.rdata)
                        response = self.query(domain, qtype, next_ip)
                        break
            else:
                ra = response.auth[0]
                if QTYPE[ra.rtype] == "NS":
                    ns_domain = str(ra.rdata)
                    ns_response = self.search(ns_domain, "A")
                    if ns_response and ns_response.rr:
                        next_ip = str(ns_response.rr[0].rdata)
                        response = self.query(domain, qtype, next_ip)
                    else:
                        return None
        if response and response.rr:
            self.ttl_cache[domain] = (response, response.rr[0].ttl, t() + response.rr[0].ttl)
            return response
        return None

class DNSResolver(BaseResolver):
    
    def __init__(self):
        self.dns = DNS()

    def resolve(self, request, handler):
        qname = str(request.q.qname)
        if not qname.endswith('.'):
            qname += '.'
        qtype = QTYPE[request.q.qtype]
        response = self.dns.search(qname, qtype)
        reply = request.reply()
        if response and response.rr:
            reply.rr = response.rr
        return reply


server = DNSServer(DNSResolver(), port=3654, address="0.0.0.0")
server.start()


