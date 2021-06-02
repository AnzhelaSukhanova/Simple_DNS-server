import socket
import time
import logging

from dnslib import *
from treelib import Tree

udp_socket = socket.socket(type=socket.SOCK_DGRAM)
udp_socket.bind(("127.0.0.1", 53))
cache = Tree()


ROOT_IP = ["198.41.0.4",
           "199.9.14.201",
           "192.33.4.12",
           "199.7.91.13",
           "192.203.230.10",
           "192.5.5.241",
           "192.112.36.4",
           "198.97.190.53",
           "192.36.148.17",
           "192.58.128.30",
           "193.0.14.129",
           "199.7.83.42",
           "202.12.27.33"]


def init_cache():
    global dom_num
    dom_num = 0
    cache.create_node("", 0, data=(ROOT_IP, 0, 0))
    dom_num += 1


def find_in_cache(zones):
    global dom_num
    par_id = 0
    depth = 0
    for z in zones:
        found = False
        for sub in cache.children(par_id):
            if sub.tag == z:
                par_id = sub.identifier
                found = True
                depth += 1
                break
        if not found:
            break
    if not found:
        for z in zones[depth:]:
            cache.create_node(z, dom_num, parent=par_id, data=(1, 0, 0))
            par_id = dom_num
            dom_num += 1
            depth += 1
        depth += 1
        ttl = int(1e5/depth)
        return (None, time.perf_counter(), ttl), par_id
    else:
        data = cache.get_node(par_id).data
        return data, par_id


def rec_find(domain, ip):
    que = DNSRecord.question(domain)
    resp = DNSRecord.parse(que.send(ip))
    if not resp.rr:
        for record in resp.ar:
            if record.rtype == 1:
                next_ip = str(record.rdata)
                return rec_find(domain, next_ip)
    else:
        return str(resp.rr[0].rdata)
    return None


def resolve(domain):
    global dom_num
    zones = domain.split('.')[-2::-1]
    (ip, last_time, ttl), par_id = find_in_cache(zones)
    if not ip or ip == 1:
        for root_ip in cache.get_node(0).data[0]:
            ip = rec_find(domain, root_ip)
            if ip:
                break
        if ip:
            cache.get_node(par_id).data = (ip, last_time, ttl)
    else:
        new_time = time.perf_counter()
        if new_time - last_time > ttl:
            for root_ip in cache.get_node(0).data[0]:
                ip = rec_find(domain, root_ip)
                if ip:
                    break
            if ip:
                cache.get_node(par_id).data = (ip, new_time, ttl)
    return ip, ttl


if __name__ == '__main__':
    init_cache()
    logging.basicConfig(level=logging.DEBUG,
                        filename='log',
                        filemode='w',
                        format='%(asctime)s - %(message)s')
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
                        ip, ttl = resolve(str(domain))
                        if ip:
                            answers.append(RR(domain, ttl=ttl, rdata=A(ip)))
                            logging.info(" IP-address for domain " + str(domain) + " is " + str(ip))
                        else:
                            logging.warning(" IP-address for domain " + str(domain) + " was not found!")
                if not answers:
                    header.rcode = 2
                header.ra = 1
                header.qr = 1
                answer = DNSRecord(header, record.questions, answers)
                udp_socket.sendto(answer.pack(), addr)
    except KeyboardInterrupt:
        udp_socket.close()
        exit(0)
