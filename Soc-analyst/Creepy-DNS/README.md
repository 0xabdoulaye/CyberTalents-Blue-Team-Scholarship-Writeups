Our NMS detect a suspected traffic, your task is to investigate the captured traffic and find the anomaly reason

# solution

i have used tshark to see what's on the dns 
`└─# tshark -Y 'dns' -r dns.pcapng`
in the dns, i see like subdomains,
```
m.cybertalents.com
Z.cybertalents.com
```
i think i need to fetch these first char on the dns. now i will ask GPT
i make the dns on a file, then i just used :
`└─# cat dns.output | grep -E '\b[a-zA-Z0-9_-]+\.cybertalents\.com\b' | awk '{print $12}'  | tee -a output2.txt`
Now i will use sublime text to remove all char i don't want.

remove spaces: `sed -i '/^[[:space:]]*$/d' output2.txt`

Now i have Repeated character i will remove them:
it's like this 
`ZZmmxxhhZZ33tt00cc22hhBBccmmttffSSXXNNffQQXXddllcczzBBttZZVV99OOZZXXRR33MMHHJJrraaWW55nnXX33RRvvMMGGxx99`
Now i make a small script:
```python
with open('output2_single_line.txt', 'r') as file:
    content = file.read()

unique_content = ''.join(char for i, char in enumerate(content) if char != content[i - 1])

with open('output2_single_line_cleaned.txt', 'w') as file:
    file.write(unique_content)

```

Now when i open the ouput: `└─# cat output2_single_line_cleaned.txt 
ZmxhZ3t0c2hBcmtfSXNfQXdlczBtZV9OZXR3MHJraW5nX3RvMGx9   `
Now i will just decoded it as base64 

```
└─# echo "ZmxhZ3t0c2hBcmtfSXNfQXdlczBtZV9OZXR3MHJraW5nX3RvMGx9" | base64 -d
flag{tshArk_Is_Awes0me_Netw0rking_to0l}
```