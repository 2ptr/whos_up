import argparse
import requests
import ipaddress
from colorama import Fore
from colorama import Style
from colorama import init as colorama_init

### Banner
banner = f"""
{Fore.BLUE}{Style.BRIGHT}*****************************************************************************{Style.RESET_ALL}{Fore.YELLOW}{Style.BRIGHT}
             _       __ __          _          __  __      ___ 
            | |     / // /_   ____ ( )_____   / / / /____ /__ \\
            | | /| / // __ \ / __ \|// ___/  / / / // __ \ / _/
            | |/ |/ // / / // /_/ / (__  )  / /_/ // /_/ //_/  
            |__/|__//_/ /_/ \____/ /____/   \____// .___/(_)   
                                                 /_/           
                                  2ptr
{Style.RESET_ALL}{Fore.BLUE}{Style.BRIGHT}*****************************************************************************{Style.RESET_ALL}"""
print(banner)

### Parser
parser = argparse.ArgumentParser(
                    prog='Who\'s Up?',
                    description='Simple and OPSEC-safe web host enumeration.',
                    epilog='https://github.com/2ptr/whos_up')

inputgroup = parser.add_argument_group('targets')
inputgroup = inputgroup.add_mutually_exclusive_group(required=True)

# Targets group
inputgroup.add_argument('-r', help='Subnet range to scan (10.10.10.0/24)', metavar='10.10.10.0/24')
inputgroup.add_argument('-rf', help='Subnet ranges file (10.10.10.0/24, 10.10.11.0/24, etc.)', metavar='subnets.txt')
inputgroup.add_argument('-tf', help='Newline-delimited single target file (10.10.10.10, 10.10.10.11, etc.)', metavar='hosts.txt')

# Configurable options
parser.add_argument('-p', help='Port list to test. Default is 80,443,8080,8443.', default='80,443,8080,8443', metavar='[ports]')
parser.add_argument('-s', help='Sleep in seconds. Default is 5s.', default=5, metavar='[num]')
parser.add_argument('-j', help='Jitter in seconds. Default is 2s.', default=2, metavar='[num]')
parser.add_argument('-ua', help='User-agent for requests. Default is from a random pool.', metavar='"Mozilla 1.x"')

parser.add_argument('-o', help='Output file for alive hosts. Defaults to web-hosts.txt.', default='web-hosts.txt',  metavar='alive.txt')

args = parser.parse_args()

settings_blob = f"""{Style.BRIGHT}{Fore.MAGENTA}[*]{Style.RESET_ALL} Scan settings:
- Ports : {args.p}
- Sleep : {args.s} seconds
- Jitter : {args.j} seconds
- User-agent: {args.ua if args.ua else 'Random (default)'}
Prese Enter to start scan...
"""

def main():
    print(settings_blob)
    input()
    # CIDR Subnet
    if(args.r):
        ips = [str(ip) for ip in ipaddress.IPv4Network(args.r)]
        print(f"{Style.BRIGHT}{Fore.YELLOW}[~]{Style.RESET_ALL} Starting scan of subnet {args.r}...")
        for ip in ips:
            pass


    # File with CIDR Subnets
    if(args.rf):
        pass

    # File with raw targets
    if(args.tf):
        pass

    return

if __name__ == '__main__':
    main()