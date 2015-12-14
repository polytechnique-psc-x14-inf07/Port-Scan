#!/usr/bin/env python
 
import time
import Queue
import threading
import logging
#logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
 
closed = 0
 
class Scanner(threading.Thread):
    """ Scanner Thread class """
    def __init__(self, queue, lock):
        super(Scanner, self).__init__()
        self.queue = queue
        self.lock = lock
 
    def run(self):
        global closed
        src_port = RandShort()
        port = self.queue.get()
        p = IP(dst=ip)/TCP(sport=src_port, dport=port, flags='S')
        resp = sr1(p, timeout=2)
        if str(type(resp)) == "<type 'NoneType'>":
            with lock:
                closed += 1
                #print "[*] %d closed" % port
        elif resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x12:
                send_rst = sr(IP(dst=ip)/TCP(sport=src_port, dport=port, flags='AR'), timeout=1)
                with lock:
                    print "[*] %d open" % port
            elif resp.getlayer(TCP).flags == 0x14:
                with lock:
                    closed += 1
                 #   print "[*] %d closed" % port
        self.queue.task_done()
 
def is_up(ip):
    p = IP(dst=ip)/ICMP()
    resp = sr1(p, timeout=10)
    if resp == None:
        return False
    elif resp.haslayer(ICMP):
        return True
 
if __name__ == '__main__':
    ip = sys.argv[1]
    bport = int(sys.argv[2])
    eport = int(sys.argv[3])
    conf.verb = 0
    start_time = time.time()
    ports = range(bport, eport)
    lock = threading.Lock()
    queue = Queue.Queue()
    if is_up(ip):
        print "Host %s is up, start scanning" % ip
        for port in ports:
            queue.put(port)
            scan = Scanner(queue, lock)
            scan.start()
        queue.join()
        duration = time.time()-start_time
        print "%s Scan Completed in %fs" % (ip, duration)
        print "%d closed ports in %d total port scanned" % (closed, len(ports))
    else:
        print "Host %s is Down" % ip
