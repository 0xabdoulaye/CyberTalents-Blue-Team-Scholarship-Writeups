can use also https://github.com/WithSecureLabs/chainsaw
i got a file log ../logs.evtx

Our network got compromised two days ago by an unknown attacker, and we need to get an answer for the following questions:

1. What is the domain's SID?
2. The attacker failed to login to some accounts, What is the attacker's machine IP address?
3. What is the workstation's name that the attacker was using to authenticate with the administrator account?

Flag format: Flag{ANS1_ANS2_ANS3}

I will use evtxtract to extract it to .xml file 

└─# python3 /root/environment/myenv/bin/evtxtract logs.evtx > logs.xml

Now have extracted,
i know the attaccker failled login and i searched on google
Look for event ID 4625 which is triggered when a failed logon is registered. Open Event Viewer in Active Directory and navigate to Windows Logs> Security. The pane in the center lists all the events that have been setup for auditing. You will have to go through events registered to look for failed logon attempts.

and i found :
`<Data Name="TargetUserName">pbarker</Data>
<Data Name="TargetDomainName">marvel.local</D
<Data Name="IpAddress">192.168.80.128</Data>
<Data Name="IpPort">44236</Data>
</EventData>`
user pbarker and found IP. now i need the SID and for fcastle also
: but these SID was same 
`<Data Name="TargetUserSid">S-1-5-21-271597537-2992796785-3713134209-1105</Data> pbarker
`
 `<Data Name="TargetUserSid">S-1-5-21-271597537-2992796785-3713134209-1103</Data> fcastle`
 in this case the domain SID will be
S-1-5-21-271597537-2992796785-3713134209 the last four number is not on it 
for the login as admin i search for event id 4776
Introduction. Event ID 4776 is logged whenever a domain controller (DC) attempts to validate the credentials of an account using NTLM over Kerberos. 
then i found :
`
<Data Name="TargetUserName">fcastle</Data>
<Data Name="Workstation">KALI</Data>
<Data Name="Status">0x00000000</Data>
but logged as fcastle
and then i found
<Data Name="TargetUserName">administrator</Data>
<Data Name="Workstation">THEPUNISHER</Data>`
Flag{S-1-5-21-271597537-2992796785-3713134209_192.168.80.128_THEPUNISHER}