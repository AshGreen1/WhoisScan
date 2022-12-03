#!/usr/bin/python3
import subprocess
import sys
from tqdm import tqdm
import pandas as pd
import re
import requests
import html2text
import os
import time
import argparse
import signal
from threading import Thread
from colorama import Fore, Style
import ipaddress
import queue
import pdb

cS = Fore.GREEN + "[✓]" + Style.RESET_ALL
pS = Fore.CYAN + "[*]"  + Style.RESET_ALL
wS = Fore.YELLOW + "[!]"  + Style.RESET_ALL
YS = Fore.YELLOW
YE = Style.RESET_ALL
GS = Fore.GREEN
GE = Style.RESET_ALL
BS = Fore.BLUE
BE = Style.RESET_ALL
RS = Fore.RED
RE = Style.RESET_ALL

def empty(data,where):
    if data != None:
        where.append(data)

def commandLine(command):
    line = subprocess.Popen([command], stdout=subprocess.PIPE, shell=True)
    (out,error) = line.communicate()
    output = out.decode()
    return output

domain = "example.com"
domainPrint = f'{GS}{domain}{GE}'
print(pS,"Analyzing", domainPrint , "this can take aroud 2 minutes...")
# subdomains
command = "subfinder -silent -d " + domain
output = commandLine(command).split("\n")
subdomainList = []
subdomainList.append(domain)
for item in output:
    empty(item,subdomainList)
many = len(subdomainList)
manyPrint = f'{GS}{str(many-1)} subdomains found!{GE}'
print(cS, manyPrint,end="\n")
subdomainList.pop(len(subdomainList)-1)
#print(subdomainList)

sub_q = queue.Queue()
out_q = queue.Queue()
init = time.time()
num_threads = 20
sub = []
for i in subdomainList:
    sub.append(i)

def pingerIps(i,q):
    while True:
        ip = q.get()
        args = ["dig", str(x)]
        p_sub = subprocess.Popen(args,
                                  shell=True,
                                  stdout=subprocess.PIPE)
        p_sub_out = str(p_sub.communicate()[0])
        pdb.set_trace()
        if (p_sub.wait() == 0):
            out_q.put(str(ip))
            print(f'{cS} {GS}{ip}{GE} is Active!')
        q.task_done()
for i in range(num_threads):
    worker = Thread(target=pingerIps, args=(i, sub_q),daemon=True)
    worker.start()
for x in sub:
    sub_q.put(x)
sub_q.join()
active = []
while True:
    try:
        msg = out_q.get_nowait()
    except queue.Empty:
        break
    active.append(msg)
