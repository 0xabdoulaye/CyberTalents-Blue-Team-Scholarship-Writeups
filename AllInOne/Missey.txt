I see Hex data but separated now i need to automate that

└─# tshark -r Missey.pcap -Y "tcp.analysis.push_bytes_sent==6" -x > hexpush.txt

found this :
70505176335852577a75324b5a4f556a4a563877344363486f72786836716b30397c464c41477b4d31355345445f494e425937247d
it's hex and i found : pPQv3XRWzu2KZOUjJV8w4CcHorxh6qk09|FLAG{M15SED_INBY7$}