we suspect that one of our server at 192.168.250.70  was attacked by a web brute forcing attack, we need to identify:

 

    X:  What is the attacker’s IP address.
    Y: The Average password length (decimal number).

Credentials: cybertalents/cybertalents

in the lessons Hunting for HTTP brute forcing attempts by counting the connections from an IP to our web server.
index=* sourcetype="stream:http" | stats count by src_ip 
first i go to the search bar and i typed
index=* sourcetype="stream:http" 
then i add the dest_ip for our server
index=* sourcetype="stream:http" dest_ip="192.168.250.70"
now i set the http method to post for logins
index=* sourcetype="stream:http" dest_ip="192.168.250.70" http_method=POST 
count it by src_IP
index=* sourcetype="stream:http" dest_ip="192.168.250.70" http_method=POST 
|  stats count by src_ip
23.22.63.114    412
40.80.148.42    12844

we found these two IPs now we will see the data for these 2 IPs
i begin with the second who have a lot of packets
for the first: index=* sourcetype="stream:http" dest_ip="192.168.250.70" http_method=POST src_ip="40.80.148.42"
and in form_data i haven't found any bruteforce.
Now for second : index=* sourcetype="stream:http" dest_ip="192.168.250.70" http_method=POST src_ip="23.22.63.114"
i found here 
username=admin&0960d493674eb04861bd64da9b662118=1&task=login&return=aW5kZXgucGhw&option=com_login&passwd=arthur
and it's the attacker IP: 23.22.63.114 
password batman length 6
flag{23.22.63.114_6}