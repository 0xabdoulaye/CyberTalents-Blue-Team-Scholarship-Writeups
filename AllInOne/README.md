- encode challenge:
first use capinfos ARP+Storm.pcap 
Number of pa
packets:   68
i used thsark 
tshark -r chall.pcap -Y arp 
also 
tshark -r ARP+Storm.pcap -Y "arp.dst.proto_ipv4 == 11.0.0.100" 
then i add 
tshark -r ARP+Storm.pcap -Y "arp.dst.proto_ipv4 == 11.0.0.100"  -T fields -e arp.opcode -E separator =, > encode.txt
make in one line and with spaces
sed ':a;N;$!ba;s/\n/ /g' encode.txt > enc0de.txt

i get these number and then  i made them in inline 
90 109 120 104 90 51 116 110 99 107 66 48 100 87 108 48 77 72 86 122 88 122 66 119 89 48 57 107 90 86 56 120 99 49 57 66 98 72 100 65 101 88 78 102 81 84 90 49 85 50 86 107 88 51 81 119 88 51 65 119 77 88 77 119 98 110 48 61 
decode it from decimal and i got 
ZmxhZ3tnckB0dWl0MHVzXzBwY09kZV8xc19BbHdAeXNfQTZ1U2VkX3QwX3AwMXMwbn0= 
base64 decode from terminale and got the flag.

- Refresher chall :
found many images then have extract them using wireshark
take first character of any 200 success images by writing a script name seded.py
then i got the 
iamsupersecretpasswordgood4uthefinding 

now look at the wireshark ftp you''
i see a zip file now extract it as raw 
now extract it using 7z x 
flag : flag{y0u_c0m3_f0r_fl1g_1nd_h3r3_1t_1s_2000}

worm challenge
crack zip and find .exe
i use pyinstxtractor to extract worm file 
foun
found worm.pyc it's interesting file
i think i need to convert that .pyc to .py 
found : https://acrosby.bitbucket.io/2018/06/28/pycdc/
extract it 
└─# ./pycdc /home/kali/Desktop/Learning/Bluteam/worm.exe_extracted/worm.pyc

flag : flag{192.168.1.0/24:22:85}

splunk
learning splunk
Splunk can be used as a single instance or as a distributed deployment. The latter would be a typical scenario for security usage in organizations, where data needs to be collected from multiple assets and sent to a centralized solution. 
SOC analysts need to make correlations and search the data, typically at different times and different physical locations.

Search Processing Language is a language designed by Splunk for use with Splunk software. It encompasses all the search commands and their functions, arguments, and clauses. 
Ressources: https://tryhackme.com/room/splunkexploringspl
Introduction to SIEM : https://tryhackme.com/room/introtosiem

SIEM stands for Security Information and Event Management system. It is a tool that collects data from various endpoints/network devices across the network, stores them at a centralized place, and performs correlation on them. This room will cover the basic concepts required to understand SIEM and how it works.
1) Host-Centric Log Sources

These are log sources that capture events that occurred within or related to the host. Some log sources that generate host-centric logs are Windows Event logs, Sysmon, Osquery, etc. Some examples of host-centric logs are:

    A user accessing a file
    A user attempting to authenticate.
    A process Execution Activity
    A process adding/editing/deleting a registry key or value.
    Powershell execution

    SOC Analyst Responsibilities

SOC Analysts utilize SIEM solutions in order to have better visibility of what is happening within the network. Some of their responsibilities include:

    Monitoring and Investigating.
    Identifying False positives.
    Tuning Rules which are causing the noise or False positives.
    Reporting and Compliance.
    Identifying blind spots in the network visibility and covering them.


    55H-access
    We observed a huge traffic towards our SSH Server 
X: How many source IPs attempting to connect  → Number
Y: The Source IP with the most connections → x.x.x.x
Z: The Source IP with the most connections country → xxxxxxx
W: The Firewall action taken from the security control → xxxxxxx
Flag format: flag{X:Y:Z:W}

search for ssh service in search filter it all time
then 
answer is 
X = src_ip = 19
Y = src_ip = top 10 : 91.224.160.108
Z = finland by googling the IPs  "https://iplocation.co.uk/ip-address/91.224.160.108"
W = blocked  : found on action value

flag{19:91.224.160.108:finland:blocked}

- FourOFour 
Massive web bruteforce attack observed on our IIS server, Your lead has informed you to initiate some investigation to identify the following :
X: The highest number of non existent URLs request sent by the attacker → Number
Y: The Source IP → x.x.x.x
Z: The attacker source country → xxx

first : IIS server all time
c_ip="40.80.148.42" sc_status="404"
X: 2009
Y = 40.80.148.42
Z = usa

flag{1315:40.80.148.42:usa} not work

x i think not correct


- usb case:
first i check provided link : https://lantern.splunk.com/Security/Use_Cases
search for usb
found : Removable devices connected to a machine

search query : sourcetype=winregistry friendlyname filter in all time

Expand the result and look at the registry_value_data field. 
X: Date and time when the USB plugged on device  (YYYY-MM-DD:HH:MM:SS)
Y: The Machine name 
Z: Name of the USB device
flag{2016-08-24:10:42:17:we8105desk:MIRANDA_PRI}


- Chall:  Remote Hacker
desc: 

Our SoC L1 reported that she received alert of suspicious login detected by company user “Kvasir” on 13/06/2022. 
Please do check and return by your analysis: 

X: Session Duration spent by the attacker on the system (HH:MM:SS) 

Y: The application used by the user after login (xxxx.exe) 

Z: Identify the SHA256 of this application W: Attacker IP address 
A: Attacker Machine host name 

transform it on xml 
evtxtract Microsoft-Windows-Sysmon_4Operational.evtx > Microsoft-Windows-Sysmon_4Operational.xml
INFO:root:recovered 20044 complete records
INFO:root:recovered 0 incomplete records

evtxtract Security.evtx > Security.xml  
INFO:root:recovered 6178 complete records
INFO:root:recovered 0 incomplete records

CTRL+F 
find 2022-06-13
<Computer>DESKTOP-9BBI1VE</Computer>
04:51:36s and 4:51:28. for kvasir
SearchIndexer.exe
autochk.exe
smss.exe
00:02:40
<Data Name="LogonType">3</Data>
<TimeCreated SystemTime="2022-06-05 13:03:18.636375"></TimeCreated>
<Data Name="IpAddress">192.168.1.58</Data>

</System>
<EventData><Data Name="RuleName">technique_id=T1204,technique_name=User Execution</Data>
<Data Name="UtcTime">2022-06-13 05:03:21.855</Data>
<Data Name="ProcessGuid">{9beb5cef-c519-62a6-1301-000000000b00}</Data>
<Data Name="ProcessId">5172</Data>
<Data Name="Image">C:\Windows\System32\win32calc.exe</Data>
<Data Name="FileVersion">10.0.17763.1 (WinBuild.160101.0800)</Data>
<Data Name="Description">Windows Calculator</Data>
<Data Name="Product">Microsoft&#174; Windows&#174; Operating System</Data>
<Data Name="Company">Microsoft Corporation</Data>
<Data Name="OriginalFileName">WIN32CALC.EXE</Data>
<Data Name="CommandLine">"C:\Windows\system32\win32calc.exe" </Data>
<Data Name="CurrentDirectory">C:\Windows\system32\</Data>
<Data Name="User">DESKTOP-9BBI1VE\kvasir</Data>
<Data Name="LogonGuid">{9beb5cef-c2f9-62a6-0c6e-040000000000}</Data>
<Data Name="LogonId">0x0000000000046e0c</Data>
<Data Name="TerminalSessionId">1</Data>
<Data Name="IntegrityLevel">High</Data>
<Data Name="Hashes">SHA1=EC73FCAB989C8D525FE3BBCC3736BC3E6192A112,MD5=46CDCA3D2EB9B837EC3C4CDA60D0D0D9,SHA256=3E2300394C15B59A964EAB45D9EB96D317650E2F7448FD1B4AE825A134402B7A,IMPHASH=BDE48881DABC2774907583E3DE072A63</Data>
<Data Name="ParentProcessGuid">{9beb5cef-c2fb-62a6-3b00-000000000b00}</Data>

flag{05:03:21:win32calc.exe:3E2300394C15B59A964EAB45D9EB96D317650E2F7448FD1B4AE825A134402B7A:192.168.1.58:Nitro}
flag{00:02:40:win32calc.exe:3E2300394C15B59A964EAB45D9EB96D317650E2F7448FD1B4AE825A134402B7A:192.168.1.58:Nitro}


chall yara Magic and WithIn Code:
YARA is the name of a tool primarily used in malware research and detection. It provides a rule-based approach to create descriptions of malware families based on textual or binary patterns
Yara Use Cases:

1. Identify Malware samples.

2. Detect Malware infection

3. Perform Incident Response and Threat Hunting activities.

- For yara first challenge :
https://support.knowbe4.com/hc/en-us/articles/360013116053-How-to-Write-YARA-Rules
I run ls:
root@nenandjabhata:/home/files/Yara Magic# ls
Folder  rule2.yara  rule.yara
i found a yara rule .
now i execute it
root@nenandjabhata:/home/files/Yara Magic# yara -f rule.yara Folder/
MySuperCoolRule Folder//12776

- Within code challenge:
I write a rule 
Flag into base64 RmxhZw= and base64 to hex 526d78685a773d3d
root@nenandjabhata:/home/files# cat rule.yara 
rule Finder
{
    strings:

            $encode = "RmxhZw=="
            $hex = "526d78685a773d3d"

        condition:
            $encode or $hex
}
root@nenandjabhata:/home/files#
when i execute it i find : root@nenandjabhata:/home/files# yara -f rule.yara Code
Finder Code/6645
 we’re going to use the -s option which will give us the offset location of the string in the matched file (for more
explanation about the Yara options use the command ($yara - - help) 
root@nenandjabhata:/home/files# yara -s -f rule.yara Code
Finder Code/6645
0x2460:$encode: RmxhZw==
we need now to decode the 0x2460 into decimal and we got 9312 as flag

- Powershell Hunting:
1. What is Powershell?
2. Powershell Hunting Commands
3. Baselines
4. Hunting Web Shells
5. Powershell Hunting Tools
6. Hunting Windows Processes

Compare :
Comparing Baselines

    $baseline = Get-Content .\baseline-services.txt
    $current = Get-Content .\current-services.txt
    Compare-Object $baseline $current
Arson:
a pcap file
i opened it using wireshark and i follwed tcp stream by http request 
i find : a powershell script in hots.ps1 
i save it as
i found this : $key = "llm0xB8WOfv9Ssq9+f0sIMFK6OyQHOzhdenMzRInqXA="
$ip = "192.168.1.11"
$port = "7788"
$implant_name = "razer"
$sleep_time = 5

i think it's a cipher AES and i found his key
i continued in the response of that request and i found this :
result=irbYP4XxfwuTlCbMxv4CE9KdquYNczFCMziT5VTG6aS%2B%2BMDZiChw3YJbtbrvt4FKO2WmdKwVBqjdX4xDguV7slrxsNNLqVbSOCceAURzkhNDvaMOIg8a0tPx3G7U%2BPUH
here is an url encryption i need to decode it : irbYP4XxfwuTlCbMxv4CE9KdquYNczFCMziT5VTG6aS++MDZiChw3YJbtbrvt4FKO2WmdKwVBqjdX4xDguV7slrxsNNLqVbSOCceAURzkhNDvaMOIg8a0tPx3G7U+PUH
This not work for our powershell script
clean all function in the script; i need decryption function:
i found this last which have razer in his post : IN3DZMA9y5D0q5y4Pe3Uv%2FVE3mA4EZY55XHJJIdLc29WAK73bE2DzB7ae%2Fmpy4CW
decode url : IN3DZMA9y5D0q5y4Pe3Uv/VE3mA4EZY55XHJJIdLc29WAK73bE2DzB7ae/mpy4CW
when i execute the powershell script i found :
 flag{2C_p0w3r_Chi11}

- Wireshark: Exodus challenge
Using http filter i get the key GET /?KEY=STAR
Now i filter icmp and i got data values :
from hex i xor these value using cyberchef and key STAR
and then from base64 i decode and find zip file 

What will you learn?
1- What is Security Onion
2- Security Onion Use Cases
3- Security Onion Platform
4- Security Onion Workflows
5- Deploying Security Onion
6- Security Onion Console
7- Security Onion Network Visibility
8- Security Onion Host Visibility
What is Security Onion?

Security Onion is a free and open platform for threat hunting, enterprise security monitoring, and log management. It includes our own tools for Alerts, Dashboards, Hunt, PCAP, and Cases as well as other tools such as Playbook, FleetDM, osquery, CyberChef, Elasticsearch, Logstash, Kibana, Suricata, Zeek, and Wazuh.
Security Onion Platform
Analysis Tools

    SOC
    Kibana
    CyberChef

Network and Host Tools
    Wazuh
    Suricata
    Zeek

Infrastructure
    Docker
    Redis
    Salt
Operating System

    Ubunto
    CentOS

    Filebeat -  Used to collect Log files and send them to logstash.
    Logstach – Used to aggregate logs.
    Redis – In memory Storage for the query for fast retrieval of the logstash.
    Elasticsearch – Indexing and Storage of logs.
    Curator – for managing Elasticsearch indexing.
Security Onion Host Visibility

Host logs can be sent to Security Onion through:

    Wazuh EDR
    Syslog
    Osquery
    Beats
    Sysmon

What will you learn?
1. Window Processes
2. Famous Windows Processes
3. Hunting Tips

Windows is the most targeted operating system by attackers, and various types of processes run in Windows, including the operating system processes and different applications processes, as a threat hunter you need to know windows processes to be able to locate abnormal behavior.
smss.exe

Responsible for starting user sessions. This process is started by the main system thread and is responsible for various activities such as starting Winlogon and Win32 (Csrss.exe) processes and setting system variables.

    Image Path: %SystemRoot%\System32\smss.exe
    Parent Process: System
    Session 0 starts csrss.exe and wininet.exe and session 1 starts csrss.exe for the user and winlogon.exe.
Mandiant RedLine

Mandiant Redline is a free tool that provides host investigative capabilities to users and uncovers signs of malicious activity through memory and file analysis to develop a threat assessment profile.

Hunting Tips:

    The most targeted process from malware authors is svchost.exe because it has multiple instances hence malware running as svchost.exe can be easily undetected.
    Malware authors tend to use a name similar to windows processes and misspell it such as:

- 1sass.exe

- svchot.exe

- cssrss.exe

    Always check the image path of the process that you suspect.
    Some malware authors use process injection techniques to inject their code inside legitimate process, you can detect process injection by checking the memory for the processes for any READ_WRITE_EXECUTE sections.

- W4nna Fl4g challenge
i use volatility 
scan pslist









Hunting Windows Events
Hunting Windows Event IDs
Hunting Accounts:

    4720: Account created
    4722: Account Enabled
    4724: reset password
    4728: user added to global group
    4756: user added to universal group

Logon Types
2
Physical login to the computer
3
A login from the network
4
Used by batch servers
5
A service started by the SCM
7
The workstation was unlocked
8
Network credentials were sent in cleartext
9
A caller specified new creds
10
A user logged in using terminal service or RDP
11
A user logged in using stored network credentials


Hunting Password Attacks

    4625: failed login.
    Logon Type 3: Network login.
Hunting Scheduled Tasks and Services

    4698: a scheduled task was created.
    200, 201: Task Monitoring and Control.
    4697: a service was installed in the system
Hunting RDP Sessions:

    4624: An account was successfully logged on.
    4778: A session was reconnected to a Window Station.

Scanner challenge
Our web server at 192.168.250.20 is being scanned by a famous vulnerability scanner, can you investigate the logs and tell us: 

    X: the vulnerability scanner name
    Y: The Source IP → x.x.x.x

Flag format: flag{X:Y}

Credentials: cybertalents/cybertalents 

I use this on splunk : 192.168.250.20 
| stats count by http_user_agent
found : Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0) 961
Nessus  36 and i now nessus is a vulnerability scanner.
I load it to see the src_ip and i found 192.168.2.50 and this 192.168.250.20
flag{Nessus:192.168.2.50} and it's correct

New account 
an attacker after compromising the machine added a new account as admin. can you find the name of the new account? 
flag format : flag{md5 of string} 

using evtxtract to extract it to xml
└─# python3 /root/environment/myenv/bin/evtxtract Security436509324654726509.evtx > security.xml

Now for hunting account we need : Hunting Accounts:

    4720: Account created
    4722: Account Enabled
    4724: reset password
    4728: user added to global group
    4756: user added to universal group

so we found <EventID Qualifiers="">4720</EventID>
and the name <EventData><Data Name="TargetUserName">Sam</Data>
we need to make this name as md5
I use md5hash generator
flag{ba0e0cde1bf72c28d435c89a66afc61a}