### Description
 You have received the alert in your company WAF that web attack happened recently. Please check and identify the below details <br>
X : Attacker IP <br> 
Y : Name of Vulnerability Scanner used by the Attacker <br>
Z : number of bytes in the sensitive files Leaked <br>
W : Date and time of the Sucessful attack (xx/xx/xxxx:xx:xx:xx) <br>
### Solution
To solve this challenge also, you need just  to know some  command line tool usage like: grep and cat

```
$ cat beansdetectorlogs | grep -e "flag.txt" -e "200 " 
172.17.0.1 - - [12/Jun/2022:11:04:11 +0000] "GET /files/skel/ HTTP/1.1" 200 184 "-" "Wfuzz/2.2" "-"
172.17.0.1 - - [12/Jun/2022:11:04:11 +0000] "GET /files/skel/.bashrc HTTP/1.1" 200 3526 "-" "Wfuzz/2.2" "-"
172.17.0.1 - - [12/Jun/2022:11:04:11 +0000] "GET /files/skel/.profile HTTP/1.1" 200 675 "-" "Wfuzz/2.2" "-"
172.17.0.1 - - [12/Jun/2022:11:04:11 +0000] "GET /files/skel/200 HTTP/1.1" 404 169 "-" "Wfuzz/2.2" "-"
172.17.0.1 - - [12/Jun/2022:11:04:15 +0000] "GET / HTTP/1.1" 200 404 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0" "-"
172.17.0.1 - - [12/Jun/2022:11:04:31 +0000] "GET /files../ HTTP/1.1" 200 2482 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0" "-"
172.17.0.1 - - [12/Jun/2022:11:04:38 +0000] "GET /files../home/ HTTP/1.1" 200 302 "http://localhost/files../" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0" "-"
172.17.0.1 - - [12/Jun/2022:11:05:12 +0000] "GET /files../home/flag.txt HTTP/1.1" 200 49 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0" "-"

```
I launch this command and in the last line i got the sensitive file flag.txt and it response successfuly with a 200 response. <br>
Now we need to answer the challenge Questions: <br>
We see that The attacker IP is 172.17.0.1, and the tool that used by the attacker is Wfuzz. <br>
The Date and time of Sucessfull attck is also in that 200 last response. and it's 12/Jun/2022:11:05:12.  We need to transform June by number, that will be 12/06/2022. <br>
The number of bytes in that sensitive files will be found near 200 response and it's "49". <br>

<li>
	<details>
		<summary>Flag</summary>
Bro, read all the Writeup and solve the challenge: the flag format is : flag{X:Y:Z:W}</details>
</li>


