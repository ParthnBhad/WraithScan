import sys
import argparse
from Scan_options.scan_functions import Scanner
from Enumeration.bannergrab import banner
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Port Scanner")
    parser.add_argument("--ip", type=str, required=True, help="IP address to scan")
    parser.add_argument("--port", type=str, required=True, help="Port or port range to scan (e.g. 80 or 80-443)")
    parser.add_argument("--TCS" , action="store_true", required=False, help="TCP Connect Scan")
    parser.add_argument("--SYN" , action="store_true", required=False, help="SYN Scan")
    parser.add_argument("--ACK" , action="store_true", required=False, help="ACK Scan")
    args = parser.parse_args()
    # Initialize the scanner object
    scanner = Scanner(args.ip, args.port)
    try:
        scanner.verify_input()
    except Exception as e:
        print(e)
        exit()
    flags = {k:v for k,v in vars(args).items() if k not in ("ip","port")}
    #Will have to make the bottom part a bit more cleaner and handle cases dynamically without causing overhead (07-08-2026)
    #Also add logging for better error tracking (07-08-2026)
    if(not any(flags.values())):
        scanner.syn_scan()
        #Banner Grabbing Added (07-08-2026) - Done
        banner(args.ip)
    if((args.TCS and args.ACK) or (args.TCS and args.SYN) or (args.SYN and args.ACK)):
        print("Please provide only one option")
        sys.exit(1)
    if(args.TCS):
        scanner.tcp_connect_scan()
    if(args.SYN):
        scanner.syn_scan()
    if(args.ACK):
        scanner.ack_scan()