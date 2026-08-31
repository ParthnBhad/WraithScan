import sys
import argparse
from Scan_options.scan_functions import Scanner
from Enumeration.bannergrab import banner
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Port Scanner")
    parser.add_argument("--ip", type=str, required=True, help="IP address to scan")
    parser.add_argument("--port", type=str, required=True, help="Port or port range to scan (e.g. 80 or 80-443)")
    
    scan_group = parser.add_mutually_exclusive_group()
    scan_group.add_argument("--TCS", action="store_true", help="TCP Connect Scan")
    scan_group.add_argument("--SYN", action="store_true", help="SYN Scan")
    scan_group.add_argument("--ACK", action="store_true", help="ACK Scan")
    scan_group.add_argument("--FIN", action="store_true", help="FIN Scan")
    scan_group.add_argument("--XMAS", action="store_true", help="XMAS Scan")
    scan_group.add_argument("--NULL", action="store_true", help="NULL Scan")
    scan_group.add_argument("--UDP", action="store_true", help="UDP Scan")
    args = parser.parse_args()
    # Initialize the scanner object
    scanner = Scanner(args.ip, args.port)
    scan_dispatch = {
        "TCS": scanner.tcp_connect_scan,
        "SYN": scanner.syn_scan,
        "ACK": scanner.ack_scan,
        "FIN": scanner.fin_scan,
        "XMAS": scanner.xmas_scan,
        "NULL": scanner.null_scan,
        "UDP": scanner.UDP_scan,
    }
    try:
        scanner.verify_input()
    except Exception as e:
        print(e)
        exit()
    #Taking arguments here as keys and the values passed to them as values
    flags = {k:v for k,v in vars(args).items() if k not in ("ip","port")}
    #Will have to make the bottom part a bit more cleaner and handle cases dynamically without causing overhead (07-08-2026)
    #Also add logging for better error tracking (07-08-2026)
    if(not any(flags.values())):
        scanner.syn_scan()
        #Banner Grabbing Added (07-08-2026) - Done
        banner(args.ip)
    else:
        for flag_name , is_set in flags.items():
            if is_set:
                scan_dispatch[flag_name]()
                break
        banner(args.ip)