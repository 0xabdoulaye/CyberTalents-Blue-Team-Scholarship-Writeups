# Description
Flag rises within the code. Our developer thinks encoding is safe, try to find the location
flag format: Flag{location}

# Solution
In this challenge, we need to know some knowledge about writing Yara rules.
i will write a yara rule for word `Flag`, Because in the challenge description it say: `Flag rises within the code.`
first i will encode the `Flag` word into `base64`, 
i will got this : `RmxhZw==` and then encode this also into `hex`, i got `526d78685a773d3d`

Now writing the rule:
Here is the Documentation: https://yara.readthedocs.io/en/stable/writingrules.html
```
rule unknown
{
	strings:
		$hex = {526d78685a773d3d}
	condition:
		$hex
}

```
When i execute it:
```terminal
root@nenandjabhata:/home/files# yara -f rule.yara Code/
unknown Code//6645
```
We got the `Code//6645` but it's not the location.
to get our location, we need to use the `-s` flag to print matching strings.

```terminal
root@nenandjabhata:/home/files# yara -s -f rule3.yara Code/
unknown Code//6645
0x2460:$hex: 52 6D 78 68 5A 77 3D 3D
```
Now we need just to decode the `0x2460` from hex to Decimal to get our location
Links : https://www.rapidtables.com/convert/number/hex-to-decimal.html
Flag{9312}