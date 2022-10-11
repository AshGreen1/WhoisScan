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
import pdb

domain = sys.argv[1]
def empty(data,where):
    if data != None:
        where.append(data)

print("Analizing " + domain + " this can take aroud 2 minutes...")
# subdomains
command = "subfinder -silent -d " + domain
subdomains = subprocess.Popen([command], stdout=subprocess.PIPE, shell=True)
(out,error) = subdomains.communicate()
output = out.decode().split("\n")
subdomainList = []
subdomainList.append(domain)
for item in output:
    empty(item,subdomainList)
many = len(subdomainList)
print(str(many-1) + " subdomains found, verifiying availibity...",end="\n")
subdomainList.pop(len(subdomainList)-1)

# DNS check for ip leakeage

info = []
for i in tqdm(subdomainList):
        if i != None:
            command = "dig " + i + "| grep -v ';' |  awk '{ print $5}'"
            urlSubdomain = subprocess.Popen([command],stdout=subprocess.PIPE,shell=True)
            (out,error) = urlSubdomain.communicate()
            details = out.split()
            detailed = []
            for n in details:
                detailed.append(n.decode())
            info.append(detailed)

#Checking the information obtained with dig

checked = []
print("Checking the information obtained with dig...",end="\n")
for i in tqdm(info):
    ipList = []
    for ip in i:
        pattern = r'\d+\.\d+\.\d+\.\d+'
        match = re.findall(pattern,str(ip))
        if bool(match) == True and not None:
            ipList.append(match[0])
    checked.append(ipList)

# ISP
ips = list(filter(None,checked))

def whois(dataip):
    r = requests.get("https://www.whatismyisp.com/ip/" + dataip)
    time.sleep(0.5)
    response = html2text.html2text(r.text)
    pattern = r'The ISP of IP\D\d+.\d+.\d+.\d+\D+'
    match = re.findall(pattern,response)
    provider = match[0].split("\n")[0]
    pattern2 = r'\d+.\d+.\d+.\d+\D+'
    match2 = re.findall(pattern2,provider)
    realProvider = match2[0].split(" ")[2]
    return realProvider

provider = []

print("Cheking the ISP provider...",end="\n")

for ip in tqdm(ips):
    ipsProvider = []
    for i in ip:
        ipsProvider.append(whois(i))
    provider.append(set(ipsProvider))

# PORTS
print("Checking most common ports...")
ports = [21,22,53,80,88,443,445,3306,5985,5986,8080]
availibity = []
for ipRange in tqdm(ips):
    PortRange = []
    for ip in ipRange:
        PortState = []
        for port in ports:
            port = str(port)
            payload = "nc -zvn -w 1 " + i + " " + port + " 1>/dev/null 2>/dev/null"
            command = os.system(payload)
            time.sleep(0.5)
            if command == 0:
                PortState.append("open")
            if command == 256:
                PortState.append("close")
        PortRange.append(PortState)
    availibity.append(PortRange)

pd.Index(data=subdomainList)
# Subdomains DataFrame

dict_subdomains = {"Domains":subdomainList}
df_subdomains = pd.DataFrame.from_dict(dict_subdomains,orient='index')
df_subdomains = df_subdomains.transpose()
print(df_subdomains,"\n")

# IP DataFrame

for i in range(0,len(ips)):
    dict_ip = {"IP":ips[i],"ISP":provider[i]}
    df_ip = pd.DataFrame.from_dict(dict_ip,orient='index')
    df_ip = df_ip.transpose()
    print(df_ip,"\n")

# Ports Dataframe
for i in range(0,len(ips)):
    port = availibity[i]
    for n in range(0,len(port)-1):
        port_ip = port[n]
        dict_ports = {"IPs Found":ips[i],"FTP": port_ip[0],"SSH":port_ip[1],"DNS":port_ip[2],"HTTP":port_ip[3],"Kerberos":port_ip[4],"SSL":port_ip[5],"SMB":port_ip[6],"MySQL":port_ip[7],"WinRM":port_ip[8],"WinRM":port_ip[9],"HTTP 8080":port_ip[10]}
        df_ports = pd.DataFrame.from_dict(dict_ports,orient='index')
        df_ports = df_ports.transpose()
        print(df_ports,"\n")
