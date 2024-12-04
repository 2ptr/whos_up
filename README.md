![Who's Up?](./whosup.png)

# Who's Up?

A basic script for when you want to take things slow in web host enumeration and avoid IDS. Provide CIDR ranges or a host list and kick back.

## Usage
```
options:
  -h, --help         show this help message and exit
  -p [ports]         Port list to test. Default is 80,443.
  --no-random        Don't randomly select hosts from subnets.
  -t [num]           Timeout in seconds. Default is 3s.
  -s [num]           Sleep in seconds. Default is 3s.
  -j [num]           Jitter in seconds. Default is 1s.
  -ua "Mozilla 1.x"  User-agent for requests. Default is Windows/Mozilla.
  -o alive.txt       Output file for alive hosts. Defaults to web-hosts.txt.
  --debug            Show all request results.

targets:
  -r 10.10.10.0/24   Subnet range to scan (10.10.10.0/24)
  -rf subnets.txt    Subnet ranges file (10.10.10.0/24, 10.10.11.0/24, etc.)
  -tf hosts.txt      Newline-delimited single target file (10.10.10.10, 10.10.10.11, etc.)
  ```
![example](./example.png)