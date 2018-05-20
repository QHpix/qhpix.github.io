---
layout: post
title: Pinkys Palace v2 Reconnaissanse
---

This writeup is split into multiple parts.
ip: 192.168.21.129
[Pinky's Palace v2](https://www.vulnhub.com/entry/pinkys-palace-v2,229/)

##Information Gathering

First, I started an nmap scan:
```
nmap -sV -v 192.168.21.129 -p-
ports:
80/tcp    open     http    Apache httpd 2.4.25 ((Debian))
4655/tcp  filtered unknown
7654/tcp  filtered unknown
31337/tcp filtered Elite
```
I went to the website, and immediately saw that it was a wordpress site.
In the network tab, I saw requests being made to `http://pinkydb/`, so I put `192.168.21.129 pinkydb` into `/etc/hosts`.
I tried to look at robots.txt, but I didn't find anything.
After that I looked at the blog posts  and found the username: pinky1337.
I used dirb to map the site: dirb http://pinkydb/ /usr/share/wordlists/dirb/common.txt and found some interesting things:
```
http://pinkydb/secret/
http://pinkydb/xmlrpc.php
```
I went to /secret/ and found a text file called `bambam.txt` with the contents:
```
8890
7000
666

pinkydb
```
When I saw 666 I immidiately thought that these were port numbers, as I've seen 666 before as a port for doom.
I tried to connect all of those ports with netcat, but got the connection refused on all of them.
After a long time scratching my head, i figured that I maybe need to connect to all the ports in some weird way.
So I searched for `port sequence` on duckduckgo and it showed a portion of a wikipedia page.
[wiki link](https://en.wikipedia.org/wiki/Port_knocking)
##Port knocking
I made a script to try all possible combinations:
```
import socket
import sys

 #################################
##QHpix' inefficient port knocker##
 #################################

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#currently only using 3 ports
arg_ports = sys.argv[2].split(':')
port_0 = int(arg_ports[0])
port_1 = int(arg_ports[1])
port_2 = int(arg_ports[2])

#define all possible combinations
ports_combs = [[port_0, port_1, port_2], 
        [port_0, port_2, port_1], 
        [port_1, port_0, port_2], 
        [port_1, port_2, port_0], 
        [port_2, port_1, port_0], 
        [port_2, port_0, port_1]]
for ports in ports_combs:
    for port in ports:
        sock.connect_ex((sys.argv[1], port))
```
This didn't seem to work, because it didn't open any new ports.
I went back to the wiki page, and took a better look at it.
In the references section I saw: `single packet authorization`, so thought that I'd have to sent _one_ packet for each port.
I also saw some mention of a _"three-knock TCP sequence"_, so I wanted to try my new script multiple times.
I planned on doing every packet of a tcp handshake.
I remembered from CyberStart Essentials that a tcp handshake starts with a SYN packet, so that was what I wanted to try first.
With that in mind, i looked up `python packet forging` on duckduckgo, and in the results I saw the name of a familiar program.
It was scapy, [https://scapy.net](https://scapy.net).
I stopped for the day and continued the day after.
After searching for hours on the internet for a better and simpler way to get all possible combinations I found permutations from itertools.
So I went to edit my script:
``
from scapy.all import IP, TCP, send
import itertools
import sys


 #####################################
## QHpix' inefficient port knocker v2##
 #####################################

def main():
    if 3 > len(sys.argv):
        error()
    port_combs = [int(p) for p in sys.argv[2].split(':')]
    port_combs = list(itertools.permutations(port_combs))
    for combo in port_combs:
        for port in combo:
            knockKnock(sys.argv[1], port)

#Knock at the door
def knockKnock(ip, port):
    #Get a map of the house
    house = IP(dst=ip, src=ip)
    #get a map of the door
    door = TCP(sport=port, dport=port, flags="S", seq=0x0)
    #walk to the door
    pkt = house/door
    #knock at the door
    send(pkt)

if __name__ == "__main__":
    main()
``
After running it multiple times: `python Qipk.v2.py 192.168.21.129 666:7000:8890`, it seemed to have worked.
The nmap output was different than before:
```
PORT      STATE SERVICE
80/tcp    open  http
4655/tcp  open  unknown
7654/tcp  open  unknown
31337/tcp open  Elite
```
I checked them all manually.
On port 4655 I received an SSH banner. _(SSH-2.0-OpenSSH 7.4p1 Debian-10+deb9u3)_
On port 7654 i found out that it was a nginx server.
I went to `http://192.168.21.129:7654/` and got '403 forbidden'.
I tried running dirb: `dirb http://192.168.21.129:7654/ /usr/share/wordlists/dirb/common.txt` and it found a directory, _'/apache/'_.
It looked like it was the root of the webserver on port 80.
I tried to go to `http://192.168.21.129:7654/apache/index.php` and instead of showing a page, it downloaded the file.
So I went to `http://192.168.21.129:7654/apache/wp-config.php` and it downloaded the file.
There were database credentials in the file:
```
DB_NAME = pwp_db
DB_USER = pinkywp
DB_PASS = pinkydbpass_wp
```
I went to `http://pinkydb:7654/` and I got a different page.
There was a link to a login page.
Used dirbuster on `http://pinkydb:7654` with the 2.3 medium wordlist.
I didn't find anything there.
I revisited CyberStart Essentials' Reconnaissance module, and was reminded about CeWL.
So I used that on the wordpress site: `cewl -w words.txt http://pinkydb/`
After that I figured, if the apache root has downloadable files, then there might be a nginx folder.
So i tried to go to `http://192.168.21.129:7654/nginx/` and it gave me 403 error, so my theory was correct.
I ran dirb with the wordlist that CeWL generated: `dirb http://192.168.21.129:7654/nginx/ words.txt`
And found a new directory, `html/`.
In that there was index.php.
I figured to try and download that as well, and it worked.
It was just a page with a link to login.php
So I downloaded that as well.
In that was a link to a new location: http://pinkydb:7654/pageegap.php?1337=filesselif1001.php

#Breaking in
This will be in the next part of my writeup
