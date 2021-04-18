
I don't know much about Lord of the rings, but this box was recommended on several sites, as a good machine to practice in prep or the OSCP. So I decided to attempt it.

# Description from VulnHub

"I created this machine to help others learn some basic CTF hacking strategies and some tools. I aimed this machine to be very similar in difficulty to those I was breaking on the OSCP."

Author: KookSec

# Getting Started

On start, the box comes with **username smeagol**

![467f0f163a9948db264a40ed00326fed.png](:/fa69f71a2a834d72824b33535c54b4d8)

***Finding the target machine on the local network?***

![be8e6a9118a4ceb899ed366bf710874e.png](:/bf2f53a39ea940bebf649229897c2f67)

ip address = ***10.0.0.13***

- `sudo nmap -Pn -sC -sV -oA nmapscans/lotr 10.0.0.13`

![065f90f4799879166dc1c284c7fb23d9.png](:/a2fd1e3f15b749ce8f2c612cfff77c94)

* * *

Looking at all ports I didn't find much

- `sudo nmap -Pn -p- 10.0.0.13`

## Port Knocking

So after a few failed brute forcing and exploit attempts, I tried to ***ssh smeagol@10.0.0.13***
probablay should have done this sooner but nevertheless.

In the image below, I see a hint ***Knock*** in the banner I see ***Easy as 1,2,3*** After some digging I found a reference to ***port knocking***

![59965cd4f2638563bda3125ceb475270.png](:/39a3b3289fb2446db1735e49bcfe05f1)

I wasn't to familar with "port knocking". I have came acrossed Vulnerbale Machines that levearge port knocking before but it had been awhile so I looked at the wiki.

For those who might be interested google port knocking and you will have plenty to read. In a nut shell, it's basically a secret handshake. This means the firewall rules are dynamic and once a certain knocking sequnence is achevied the firewall allows predetermined access to a service.

I found several nmap articles, that show "port knocking" example commands but the one that worked seem to be the following sequnce:

- `nmap -r -Pn -p1,2,3 10.0.0.13`
- `nmap -Pn -p- 10.0.0.13`

I had tried to run the above commands earlier and it didn't work, but after a reboot the above nmap commands did work. I finally see a another service on port 1337

![7897979d8b30d233038b4b63f074a0c1.png](:/6e55e7df78404874bf381cf04737fab1)

Ran `nmap -Pn -p1337 -sV 10.0.0.13` to determine what the service was running. Apache 2.4.7

![0101c172b99f95dde4f7c80c7671f5f8.png](:/9d96f87405ac4dd8989779c69e9bcc7a)

Ran a quick dirb scan using `dirb http://10.0.0.13:1337/`

```
---- Scanning URL: http://10.0.0.13:1337/ ----
==> DIRECTORY: http://10.0.0.13:1337/images/                                              
+ http://10.0.0.13:1337/index.html (CODE:200|SIZE:64)                                     
+ http://10.0.0.13:1337/server-status (CODE:403|SIZE:291)                                 
                                                                                          
---- Entering directory: http://10.0.0.13:1337/images/ ----
```

Several URLs listed

```
http://10.0.0.13:1337/images/
http://10.0.0.13:1337/index.html
http://10.0.0.13:1337/server-status
http://10.0.0.13:1337/images/
```

Diving into the URLs from the "dirb scan", I didn't find anything anything interesting until trying.

`http://10.0.0.13:1337/index.html/`

**Looking at the Page:**

![25a8de67bcf42e94938deaf1e5c01bfa.png](:/1f572564dc8d4bec849049b3ab6a9f82)

**Viewing the source I see:**

![d5c7429c07ffb93985eb0a272d28942e.png](:/674acb1f528642eb89e4994a5fd252e7)
**Looks like base64 so I ran the standard:**

`echo 'THprM09ETTBOVEl4TUM5cGJtUmxlQzV3YUhBPSBDbG9zZXIh' | base64 -d`

![e0a82dd6fb809273c01e16a34cf85e87.png](:/b0d9bbf984d74d2f9c457c5f9e5ef506)

**Once again, it looks like base64 so taking the output of our previous decoding  I see:**

`echo 'Lzk3ODM0NTIxMC9pbmRleC5waHA=' | base64 -d`

![56be965ee322198b7b1d07621e3460ef.png](:/878246becd274df9bac9fe92c161699d)

`http://10.0.0.13:1337/978345210/index.php` I see:

![bc30e48031c29cf3a45dd9d0251b03a6.png](:/72f770e5bd4c4838a3366e1a7f1fe80a)

Great! A login this looks promising!

Spent some time enumerating the box and eventually got hit using SQLMAP. This was after many failed login attempts. Don't get discouraged here. I know I did, I was stuck here for a little bit. This took me many attempts and I looked at several resources to finally get something that would work. Even when I got it to work it took a long time.

`python3 sqlmap.py -url http://10.0.0.13:1337/978345210/index.php --forms --dbs --level=5 --risk=3 --batch -D Webapp --dump all`

![e497dd83dce907a9d22b3d9349b7d1ab.png](:/2a7709db8859406cb469a0a8613b4765)

Finally a shell

![5f1cb8823b26640e582310c75840b02e.png](:/f491c21b66ff4e2fa5502b2a52ac76fa)

![5ce0d4842c4dd89fe2d23a4b3b947975.png](:/f12668dc4a784b749247e0c64167b257)

I dug around a little bit, but decided to run linpeas [Link](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite), I chose the quick method and used filezilla to transfer the file. Then ran the script.

Linpeas will print out alot of informaiton but the first thing I noticed was it flagged the OS.

![0d4b746264041726fce5ca9cbfcc099b.png](:/92d5b693649441e8b8f01d0032470d57)

It also list software on the vulnerable machine, that could assist you.

![e12a2984859b360fee9cd432faa5a356.png](:/c98534210a9b48dfb4b5a71f9418af04)

So I googled `Ubuntu 14.04.3 ` exploits

You can find the vuln [here](https://www.exploit-db.com/exploits/39166)

I downloaded the Exlploit

- Moved the c file it to the vuln machine using filezilla
- complied it with `gcc 39166.c -o vulnpop`
- ran the exe with `./vulnpop`

Tada! We are root!

![967b1bb932272000601122699ff0f5a9.png](:/7196dff360514c99bf6e5e0db5ff1cc0)
