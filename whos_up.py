import argparse
import requests
import ipaddress
from time import sleep
import random
from colorama import Fore
from colorama import Style
from colorama import init as colorama_init
import warnings

warnings.filterwarnings("ignore")
### Banner
banner = f"""
{Fore.BLUE}{Style.BRIGHT}*****************************************************************************{Style.RESET_ALL}{Fore.YELLOW}{Style.BRIGHT}
             _       __ __          _          __  __      ___ 
            | |     / // /_   ____ ( )_____   / / / /____ /__ \\
            | | /| / // __ \ / __ \|// ___/  / / / // __ \ / _/
            | |/ |/ // / / // /_/ / (__  )  / /_/ // /_/ //_/  
            |__/|__//_/ /_/ \____/ /____/   \____// .___/(_)   
                                                 /_/           
                                  {Fore.WHITE}2ptr

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
parser.add_argument('-p', help='Port list to test. Default is 80,443.', default='80,443', metavar='[ports]')
parser.add_argument('--no-random', help='Don\'t randomly select hosts from subnets.', action="store_true")
parser.add_argument('-s', help='Sleep in seconds. Default is 5s.', default=5, type=int, metavar='[num]')
parser.add_argument('-j', help='Jitter in seconds. Default is 2s.', default=2, type=int, metavar='[num]')
parser.add_argument('-ua', help='User-agent for requests. Default is from a random pool.', metavar='"Mozilla 1.x"')

parser.add_argument('-o', help='Output file for alive hosts. Defaults to web-hosts.txt.', default='web-hosts.txt',  metavar='alive.txt')

args = parser.parse_args()

settings_blob = f"""{Style.BRIGHT}{Fore.MAGENTA}[*]{Style.RESET_ALL} Scan settings:
- Ports : {args.p}
- Target Selection : {'Sequential' if args.no_random else 'Random'}
- Sleep : {args.s} seconds
- Jitter : {args.j} seconds
- User-agent: {args.ua if args.ua else 'Random (default)'}
>> Press Enter to start scan..."""

def all_elements_in(list_a, list_b):
    """Check if all elements of list_a are in list_b."""
    return all(item in list_b for item in list_a)

def main():
    print(settings_blob)
    ports = args.p.split(',')
    input()

    # CIDR Subnet
    if(args.r):
        # Generate all target connection strings (ports included)
        ips = [str(ip) for ip in ipaddress.IPv4Network(args.r)]
        targets = []
        for ip in ips:
            for port in ports:
                targets.append(f"{ip}:{port}")

        print(f"{Style.BRIGHT}{Fore.YELLOW}[~]{Style.RESET_ALL} Starting scan of subnet {args.r} - {len(targets)} targets")

        # Scan
        scanned = []
        target = random.choice(targets)
        for i in targets:
            while target in scanned:
                target = random.choice(targets)
            print(f"\r\\--> {target}", end="")
            # Try HTTP and then check exceptions
            try:
                # "Sleep" is just our timeout
                response = requests.get(f"http://{target}", timeout=2)
                print(f"{Style.BRIGHT}{Fore.GREEN}[+]{Style.RESET_ALL} http://{Style.RESET_ALL}{target} is up!")
            except requests.exceptions.SSLError:
                response = requests.get(f"https://{target}", timeout=10, verify=False)
                print(f"{Style.BRIGHT}{Fore.GREEN}[+]{Style.RESET_ALL} https://{target} is up!")
            except requests.exceptions.SSLError:
                print(f"{Style.BRIGHT}{Fore.GREEN}[+]{Style.RESET_ALL} https://{target} has an SSL error.")
            except requests.exceptions.ReadTimeout:
                print(f"{Style.BRIGHT}{Fore.GREEN}[+]{Style.RESET_ALL} https://{target} timed out, but is likely up.")
            except:
                # print(f"{target} is down.")
                pass
            
            # "Jitter" is inbetween jobs
            sleep(args.s + random.randint(0,args.j))
            scanned.append(target)
        


    # File with CIDR Subnets
    if(args.rf):
        pass

    # File with raw targets
    if(args.tf):
        pass

    return

if __name__ == '__main__':
    main()