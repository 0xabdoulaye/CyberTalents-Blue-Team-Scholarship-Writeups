### Description 
Our SoC L1 reported that she received alert of suspicious login detected by company user “Kvasir” on 13/06/2022. <br>
Please do check and return by your analysis: <br>

X: Session Duration spent by the attacker on the system (HH:MM:SS) <br>

Y: The application used by the user after login (xxxx.exe) <br>

Z: Identify the SHA256 of this application W: Attacker IP address <br>

A: Attacker Machine host name <br>

Flag format: flag{X:Y:Z:A}<br>


### Solution
To solve this challenge, Many people used Windows OS to analyze this file. I used Linux to Solve it and here is how i proceed. <br>

On github, i found a tool named evtxtract, that can help me to transform my evtx into xml file. Then i install it. <br>
Now i proceed for conversion for evtx files .<br>
```
$ evtxtract Microsoft-Windows-Sysmon_4Operational.evtx > Windows-Sysmon_4Operational.xml
INFO:root:recovered 20044 complete records
INFO:root:recovered 0 incomplete records
```
```
$ evtxtract Security.evtx > Security.xml  
INFO:root:recovered 6178 complete records
INFO:root:recovered 0 incomplete records
```
Now, on the description i see that the supscious login was detected on 13/06/2022. I click on CTRL+F and try to find that date on the Security.xml file. <br>
Then , I found the computer name on a date 2022-06-13 <br>
```
<Computer>DESKTOP-9BBI1VE</Computer> <br> 
```
For the Session Duration spent by the attacker on the system, You need to identify the login then also check the logoff and calculate it. <br>
I found also the IP adress in the XML code, and this LogonType <br>
In Windows, LogonType codes are used to identify different types of logon events for security auditing purposes. The value "3" for "LogonType" typically indicates a network logon, which means a user has connected to a remote system (over the network) and logged in with their credentials. <br>
```
<Data Name="LogonType">3</Data>
<Data Name="LogonProcessName">NtLmSsp </Data>
<Data Name="AuthenticationPackageName">NTLM</Data>
<Data Name="WorkstationName">Nitro</Data>
<Data Name="TransmittedServices">-</Data>
<Data Name="LmPackageName">-</Data>
<Data Name="KeyLength">0</Data>
<Data Name="ProcessId">0x0000000000000000</Data>
<Data Name="ProcessName">-</Data>
<Data Name="IpAddress">192.168.1.58</Data>
<Data Name="IpPort">0</Data>
<br> 
```
Find IP address and Workstation Name.
To find the Application used by the attacker, we should look for a process created by a user. <br>
In Sysmon (System Monitor), a process creation event with an ID of "1" refers to the process creation event type. Sysmon is a Windows system service and device driver that monitors and logs various system activities to help detect and investigate potential security threats. <br>
So now, we need to return and look at when the user logged into the system and then read the events by date <br>
We will find sethc.exe, Win32calc.exe and then identify which one of these applications is started by the ParentUser. You will find that application Sha256. <br>

<li>
	<details>
		<summary>Flag</summary>
Tryharder bro.. If you don't understand all of these step. ping me on Discord: blomann#3219. for some explanation. Thanks...</details>
</li>
