#!/usr/bin/env python

import time
import multiprocessing
import logging
from scapy.all import *

closed = 0

def scan(port):
    closed = 0
    global openp
    src_port = RandShort()
    p = IP(dst=ip)/TCP(sport=src_port, dport=port, flags='S')
    resp = sr1(p, timeout=2)
    if str(type(resp)) == "<type 'NoneType'>":
        closed += 1
        #print "[*] %d closed" % port
    elif resp.haslayer(TCP):
        if resp.getlayer(TCP).flags == 0x12:
            send_rst = sr(IP(dst=ip)/TCP(sport=src_port, dport=port, flags='AR'), timeout=1)
            print "[*] %d open" % port
        elif resp.getlayer(TCP).flags == 0x14:
            closed += 1
            #print "[*] %d closed" % port
    return closed

def is_up(ip):
    p = IP(dst=ip)/ICMP()
    resp = sr1(p, timeout=10)
    if resp == None:
        return False
    elif resp.haslayer(ICMP):
        return True

if __name__ == '__main__':
    ip = sys.argv[1]
    bport = sys.argv[2]
    eport = sys.argv[3]
    conf.verb = 0
    start_time = time.time()
    ports = range(bport, eport)
    pool = multiprocessing.Pool(processes=multiprocessing.cpu_count()*10)
    if is_up(ip):
        print "Host %s is up, start scanning" % ip
        results = [pool.apply_async(scan, (port,)) for port in ports]
        for result in filter(lambda i : i.get() != None, results):
            closed += result.get()
        duration = time.time()-start_time
        print "%s Scan Completed in %fs" % (ip, duration)
        print "%d closed ports in %d total port scanned" % (closed, len(ports))
    else:
        print "Host %s is Down" % ip
