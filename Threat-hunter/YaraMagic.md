# Description
Help us!Here is a copy of a folder of ours, 
we need to scan this folder with this Yara rule and check if we have any matches!,
 scan this folder with the rule and provide us with the matched filename.
Flag format: FLAG{filename}

# SOlution
The challenge provide us a yara rule, we need only to run it on this folder
here is the rule:
```
root@nenandjabhata:/home/files/Yara Magic# cat rule.yara 
rule MySuperCoolRule
{
    strings:
       
        $my_hex_string = { 54 4f 4b 41 }

    condition:
         $my_hex_string 
}

```
I just run
```terminal
root@nenandjabhata:/home/files/Yara Magic# yara -f rule.yara Folder/
MySuperCoolRule Folder//12776
```

`FLAG{12776}`