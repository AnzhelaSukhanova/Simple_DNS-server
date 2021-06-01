import dns.resolver
import socket
import time

from dnslib import DNSRecord, RR, A
from treelib import Tree

udp_socket = socket.socket(type=socket.SOCK_DGRAM)
udp_socket.bind(("127.0.0.1", 53))
cache = Tree()

resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = ["8.8.8.8", "8.8.4.4"]


def init_cache():
    global dom_num
    dom_num = 0
    cache.create_node("", 0)
    cache.create_node("ru", 1, parent=0)
    cache.create_node("com", 2, parent=0)
    cache.create_node("org", 3, parent=0)
    dom_num += 4


def find_in_cache(zones):
    global dom_num
    par_id = 0
    ind = 0
    for z in zones:
        found = False
        for sub in cache.children(par_id):
            if sub.tag == z:
                par_id = sub.identifier
                found = True
                ind += 1
                break
        if not found:
            break
    if not found:
        for z in zones[ind + 1:]:
            cache.create_node(z, dom_num, parent=par_id)
            par_id = dom_num
            dom_num += 1
        return ("", time.perf_counter()), (ind, par_id)
    else:
        data = cache.get_node(par_id).data
        return data, (ind, par_id)


def resolve(domain):
    global dom_num
    zones = domain.split('.')[1::-1]
    (ip, last_time), (ind, par_id) = find_in_cache(zones)
    if ip == "":
        answer = resolver.resolve(domain, raise_on_no_answer=False)
        ip = answer.rrset.to_text().split()[-1]
        cache.create_node(zones[ind], dom_num, parent=par_id, data=(ip, last_time))
        dom_num += 1
    else:
        new_time = time.perf_counter()
        if new_time - last_time > 1e4:
            answer = dns.resolver.resolve(domain, raise_on_no_answer=False)
            ip = answer.rrset.to_text().split()[-1]
            cache.get_node(par_id).data = (ip, new_time)
    return ip


if __name__ == '__main__':
    init_cache()
    try:
        while True:
            data, addr = udp_socket.recvfrom(1024)
            record = DNSRecord.parse(data)
            header = record.header
            qr = header.qr
            rcode = header.rcode
            if not qr and not rcode:
                answers = []
                for que in record.questions:
                    domain = que.qname
                    if que.qtype == 1:
                        ip = resolve(str(domain))
                        header.qr = 1
                        answers.append(RR(domain, rdata=A(ip)))
            answer = DNSRecord(header, record.questions, answers)
            udp_socket.sendto(answer.pack(), addr)
    except KeyboardInterrupt:
        udp_socket.close()
        exit(0)
