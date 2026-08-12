#figure out a way to work dynamically using range of ports and IPs and their management. (25/07/2026)
from scapy.volatile import RandShort
import socket as s
from scapy.all import IP, TCP, sr, UDP, ICMP
from concurrent.futures import ThreadPoolExecutor
import sys

class Scanner:
    def __init__(self, ip, ports):
        self.ip = ip
        self.ports = ports
    
    def verify_input(self):
        if "-" in self.ports:
            start, end = self.ports.split("-")
            if(start.isdigit() and end.isdigit()):
                if(int(start) > int(end)):
                    raise ValueError("start port can't be greater than end port")
                if int(start) < 0 or int(end) > 65535:
                    raise ValueError("port number is out of range")
                self.ports = range(int(start), int(end) + 1)
            else:
                raise ValueError("Invalid input for port")
        else:
            try:
                if(self.ports.isdigit() is False):
                    raise ValueError("port number is not a number")
                elif(int(self.ports) > 65535 or int(self.ports) < 0):
                    raise ValueError("Port number is out of range")
                else:
                    self.ports = [int(self.ports)]
            except ValueError as Ve:
                print(Ve)
                sys.exit(1)
            except Exception as e:
                print("unkown error occured printing error : ")
                print(e)
                sys.exit(1)
        try:
            if len(self.ip.split(".")) == 4 and all(x.isdigit() and 0 <= int(x) <= 255 for x in self.ip.split(".")):
                pass
            else:
                raise ValueError("Invalid ip")
        except ValueError as Ve:
            print(Ve)
            sys.exit(1)

    def tcp_connect_scan(self): #Connect scan which actually establishes a connection to the target.
        def scan_single(port):
            with s.socket(s.AF_INET, s.SOCK_STREAM) as sock:
                sock.settimeout(2)
                try:
                    res = sock.connect((self.ip, port)) #remember that res will be none so if a successfull scan is done it will be none.
                    print(f"port {port} is open")
                except (ConnectionAbortedError , ConnectionRefusedError, s.timeout):
                    pass
                except PermissionError:
                    print("Run as Root/Admin --> --_-- ...>(why did you do that?)")
                except Exception as e:
                    print(f"Unexpected Error on port {port}: {e}")

        # Note: Fixed the indentation here. ThreadPoolExecutor shouldn't be inside scan_single. Synchronus uses a lot of time.
        #use asynchronus methods to improve efficiency. (31-07-2026)
        with ThreadPoolExecutor(max_workers=100) as ex:
            ex.map(scan_single, self.ports)

    def syn_scan(self): #syn scan should be kept as a default scan.
        pkt = (IP(dst=self.ip)/TCP(sport=RandShort(), dport=list(self.ports), flags="S"))
        try:
            ans, unans = sr(pkt, timeout=2 , verbose=0)
            for sent, recv in ans:
                if(recv.haslayer(TCP)):
                    if(recv[TCP].flags == "SA"):
                        print(f"port {recv[TCP].sport} is open")
                    elif(recv[TCP].flags in ("RA", "R")):
                        continue #making it not print close values.
                    else:
                        print(f"Returned unexpected flags {recv[TCP].flags}")
                else:
                    pass
            for sent_pkt in unans:
                pass
        except Exception as e:
            print("unknown Error")
            print(e)
    def ack_scan(self):
        pkt = (IP(dst=self.ip)/TCP(sport=RandShort(), dport=list(self.ports), flags="A"))
        try:
            ans , unans = sr(pkt, timeout=2, verbose=0)
            for sent , recv in ans:
                if(recv.haslayer(TCP)):
                    if(recv[TCP].flags in ("R","RA")):
                        print(f"port {recv[TCP].sport} is unfiltered")
                    else:
                        pass
                else:
                    pass
            for sent_pkt in unans:
                pass
        except Exception as e:
            print("Unknown Error")
            print(e)
    def fin_scan(self):
        pkt = (IP(dst=self.ip)/TCP(sport=RandShort(), dport=list(self.ports), flags="F"))
        try:
            ans, unans = sr(pkt, timeout=2, verbose=0)
            for sent, recv in ans:
                if(recv.haslayer(TCP)):
                    if(recv[TCP].flags in ("R","RA")):
                        print(f"port {recv[TCP].sport} is closed")
                    else:
                        pass
                else:
                    pass
            for sent_pkt in unans:
                pass
        except Exception as e:
            print("Unknown Error")
            print(e)
    def xmas_scan(self):
        pkt = (IP(dst=self.ip)/TCP(sport=RandShort(), dport=list(self.ports), flags="FPU"))
        try:
            ans, unans = sr(pkt, timeout=2, verbose=0)
            for sent, recv in ans:
                if(recv.haslayer(TCP)):
                    if(recv[TCP].flags in ("R","RA")):
                        print(f"port {recv[TCP].sport} is closed")
                    else:
                        pass
                else:
                    pass
            for sent_pkt in unans:
                pass
        except Exception as e:
            print("Unknown Error")
            print(e)
    def null_scan(self):
        pkt = (IP(dst=self.ip)/TCP(sport=RandShort(), dport=list(self.ports), flags=""))
        try:
            ans, unans = sr(pkt, timeout=2, verbose=0)
            for sent, recv in ans:
                if(recv.haslayer(TCP)):
                    if(recv[TCP].flags in ("R","RA")):
                        print(f"port {recv[TCP].sport} is closed")
                    else:
                        pass
                else:
                    pass
            for sent_pkt in unans:
                pass
        except Exception as e:
            print("Unknown Error")
            print(e)
    def UDP_scan(self):
        pkt = (IP(dst=self.ip)/UDP(sport=RandShort(),dport=list(self.ports)))
        ans, unans = sr(pkt,timeout=2,verbose=0)
        for sent, recv in ans:
            try:
                if(recv.haslayer(UDP)):
                    #A response is returned so it means the port is open
                    print(f"{recv[UDP].sport} is Open")
                else:
                    if(recv.haslayer(ICMP)):
                        #A response is returned but it is not a udp response
                        if(recv[ICMP].type == 3 and recv[ICMP].code == 3):
                            pass
                        elif(recv[ICMP].type == 3 and recv[ICMP].code in [1,2,9,10,13]):
                            pass
                        else:
                            #to capture unknown icmp messages
                            pass
                    else:
                        #to capture unknown messages
                        pass
            except TimeoutError as Te:
                pass
            except KeyboardInterrupt:
                print("Scan Interrupted")
                sys.exit(-1)
            except Exception as e:
                print("Unknown Error")
                print(e)
        for sent_pkt in unans:
            #if no response for the sent udp packet this case usually means that the port is open or filtered
            print(f"port {sent_pkt[UDP].dport} is open|filtered")