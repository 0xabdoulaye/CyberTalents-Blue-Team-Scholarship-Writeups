### Description
Our server compromised due to known vulnerability introduced from many years, Kindly check and identify this flow 

X: Attack source → EX. “Internal/External”
Y: The Source IP → x.x.x.x
Z: CVE Num of the attack → xxx
W: Destination Mac Address
Flag format: flag{X:Y:Z:w}

### Solution
First I used capinfos to see informations of the file
```
$ capinfos backdoor.pcap 
File name:           backdoor.pcap
File type:           Wireshark/tcpdump/... - pcap
File encapsulation:  Ethernet
File timestamp precision:  microseconds (6)
Packet size limit:   file hdr: 96 bytes
Packet size limit:   inferred: 96 bytes
Number of packets:   739
File size:           71 kB
Data size:           134 kB
Capture duration:    72.785513 seconds
First packet time:   2022-04-26 18:07:31.244931
Last packet time:    2022-04-26 18:08:44.030444
Data byte rate:      1,850 bytes/s
Data bit rate:       14 kbps
Average packet size: 182.21 bytes
Average packet rate: 10 packets/s
SHA256:              91a780295b31dac44d5357bf63bfe2cfddb990f447fd60a9048eb16ec5c7ec15
RIPEMD160:           01a55a5fe78f4db4ae13d90b031b6d5e5c8845fd
SHA1:                6a8a80c755676757b2a77b01f0282c46b4f87f9d
Strict time order:   True
Number of interfaces in file: 1
Interface #0 info:
                     Encapsulation = Ethernet (1 - ether)
                     Capture length = 96
                     Time precision = microseconds (6)
                     Time ticks per second = 1000000
                     Number of stat entries = 0
                     Number of packets = 739

```
I see number of packets is 739. now i proceed with Tshark, i used tshark to search if this pcap have a http request but not. Then i try to search for FTP.
```
$ tshark -r backdoor.pcap -Y ftp
Running as user "root" and group "root". This could be dangerous.
  165  10.000115 192.168.1.80 → 192.168.1.58 FTP 86 Response: 220 (vsFTPd 2.3.4)
  167  10.000865 192.168.1.58 → 192.168.1.80 FTP 78 Request: USER zH9:)
  169  10.000901 192.168.1.80 → 192.168.1.58 FTP 100 Response: 331 Please specify the passwor
  171  10.001580 192.168.1.58 → 192.168.1.80 FTP 77 Request: PASS utEt

```
I got only 4 request. So, in the first request i see vsFTPD 2.3.4 and it's the vulnerability that allowed the attacker to hack the machine.
I search that on Google and i got CVE-2011-2523. 
Also, you can see that in these FTP request, you will see the source IP, that's 192.168.1.58,  and destination IP : 192.168.1.80.
Now if you use wireshark and filter using FTP. you will find the Destination Mac address.
or use this wireshark command 

```
$ tshark -r backdoor.pcap -Y ftp -V | less
Frame 165: 86 bytes on wire (688 bits), 86 bytes captured (688 bits)
    Encapsulation type: Ethernet (1)
    Arrival Time: Apr 26, 2022 18:07:41.245046000 EDT
    [Time shift for this packet: 0.000000000 seconds]
    Epoch Time: 1651010861.245046000 seconds
    [Time delta from previous captured frame: 0.005825000 seconds]
    [Time delta from previous displayed frame: 0.000000000 seconds]
    [Time since reference or first frame: 10.000115000 seconds]
    Frame Number: 165
    Frame Length: 86 bytes (688 bits)
    Capture Length: 86 bytes (688 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: eth:ethertype:ip:tcp:ftp]
Ethernet II, Src: PcsCompu_66:e3:8b (08:00:27:66:e3:8b), Dst: IntelCor_c5:20:65 (4c:1d:96:c5:20:65)

```
You will find the Destination Mac address: 08:00:27:66:e3:8b
<li>
	<details>
		<summary>Flag</summary>
flag{Internal:192.168.1.58:CVE-2011-2523:08:00:27:66:e3:8b}</details>
</li>
