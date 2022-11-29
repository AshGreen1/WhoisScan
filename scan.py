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
from multiprocessing.pool import ThreadPool as Pool
import colorama
from colorama import Fore, Style
import pdb
import ipaddress
from pythonping import ping
#import concurrent.futures

cS = Fore.GREEN + "[✓]" + Style.RESET_ALL
pS = Fore.CYAN + "[*]"  + Style.RESET_ALL
GS = Fore.GREEN
GE = Style.RESET_ALL

def def_handler(sig, frame):
    print(Fore.RED,"\nKilling all the processes...\n",Style.RESET_ALL)
    sys.exit(1)

# Ctrl + C
signal.signal(signal.SIGINT, def_handler)

parser = argparse.ArgumentParser()
portHelp = "\tScan the common ports in a IP range (Need a file with the IPs)"
depthHelp = "\tDigging deeper into the subdomains (Need to be used with -u)"
#outHelp = "\tExport the scan as it is displayed"
csvHelp = "\tExport the scan as a CSV"
parser.add_argument("-u", "--url", help="\tThe url to scan")
parser.add_argument("-i", "--ip", help="\tA IP to scan")
parser.add_argument("-p", "--ports", help=portHelp)
parser.add_argument("-d", "--depth", help=depthHelp,action="store_true")
#parser.add_argument("-oN", "--output", help=outHelp)
parser.add_argument("-c", "--csv", help=csvHelp,action="store_true")
args = parser.parse_args()

# Export DataFrame as csv

def csvExport(data):
    os.makedirs('scanned/', exist_ok=True)
    now = time.localtime()
    timeNow = time.strftime("%m-%d-%Y-%H-%M-%S", now)
    data.to_csv(f"scanned/dataFrame-{timeNow}.csv")

# Handle a command

def commandLine(command):
    line = subprocess.Popen([command], stdout=subprocess.PIPE, shell=True)
    (out,error) = line.communicate()
    output = out.decode()
    return output

# Check if empty

def empty(data,where):
    if data != None:
        where.append(data)

# Deepens the argument -u

def depth(subdomainList):
    # DNS check
    info = []
    for i in tqdm(subdomainList):
            if i != None:
                command = f"dig {i} | grep -v ';' |" + "  awk '{ print $5 }'"
                details = commandLine(command).split()
                detailed = []
                for n in details:
                    detailed.append(n)
                info.append(detailed)
    checked = []
    print(pS, "Checking the information obtained with dig...",end="\n")
    # Filtering IPs
    for i in tqdm(info):
        ipList = []
        for ip in i:
            pattern = r'\d+\.\d+\.\d+\.\d+'
            match = re.findall(pattern,str(ip))
            if bool(match) == True and not None:
                ipList.append(match[0])
        checked.append(ipList)
    ips = list(filter(None,checked))
    # Check ISP provider
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
    print(pS,"Cheking the ISP provider...",end="\n")
    for ip in tqdm(ips):
        ipsProvider = []
        for i in ip:
            ipsProvider.append(whois(i))
        provider.append(ipsProvider[0])
    # Create a DataFrame
    dict_info = {"Subdomains":subdomainList,"IP":ips,"Provider":provider}
    df = pd.DataFrame.from_dict(dict_info, orient="index")
    df = df.transpose()
    return df.set_index("Subdomains")

# Check for subdomains

def subdomainScan(domain):
    domainPrint = Fore.GREEN + domain + Style.RESET_ALL
    print(pS,"Analyzing", domainPrint , "this can take aroud 2 minutes...")
    # subdomains
    command = "subfinder -silent -d " + domain
    output = commandLine(command).split("\n")
    subdomainList = []
    subdomainList.append(domain)
    for item in output:
        empty(item,subdomainList)
    many = len(subdomainList)
    manyPrint = Fore.GREEN + str(many-1)+ " subdomains found!" + Style.RESET_ALL
    print(cS, manyPrint,end="\n")
    subdomainList.pop(len(subdomainList)-1)
    # Check if depth is TRUE
    if args.depth:
        dig = depth(subdomainList)
        return dig
    else:
        row = Fore.BLUE + "Subdomains" + Style.RESET_ALL
        df = pd.DataFrame({row:subdomainList})
        return df

# Check for a IP range
## Scan a IP range
## Scan the IP looking for a IP range
def ipScan(ip):
    ipSPrint = Fore.GREEN + ip + Style.RESET_ALL
    print(f'{pS} Analyzing IP {ipSPrint}')
    regex = '| grep "\b[0-9]*. - [0-9]*.*\B[0-9]" '
    regex += '| awk -F ":" "{print $2}" | sed "s/ //g"'
    command = f'whois {ip}'
    output = commandLine(command).replace("\n","")
    pattern_range = r'\d+\.\d+\.\d+\.\d+/\d\d'
    output = re.findall(pattern_range, output)
    ipRangeFound = Fore.GREEN + output[0] + Style.RESET_ALL
    print(f'{cS} The Ip range {ipRangeFound} was found!')
    #pdb.set_trace()
    def Ips(ips):
        active = []
        for ip in ipaddress.IPv4Network(ips[0]):
            command = f'ping -c 1 -w 1 {format(ip)} '
            command += '2>/dev/null 1>/dev/null; echo $?'
            pingCommand = commandLine(command)
            #pdb.set_trace()
            #print(pingCommand)
            if int(pingCommand.strip()) == 0:
                print(f'{cS} {GS}{ip}{GE} is Active!')
                active.append(format(ip))
            #print("There are",len(active),"active targets",end="\n", flush=True)
        df_ips = {"Active":active}
        df = pd.DataFrame.from_dict(df_ips, orient='index')
        return df.transpose()
    Ips(output)
    #pool_size = 5
    #for _ in range(10):
    #    Pool.apply_async(Ips, (output,))
    #Pool.close()
    #Pool.join()

# Scanning Ports from IP file

def portScan(ipsFile):
    print(pS,"Checking most common ports...")
    ips = list(open(ipsFile))
    ports = [21,22,53,80,88,443,445,3306,5985,5986,8080]
    availibity = []
    n = 0
    while n < len(ips):
        PortRange = []
        for port in tqdm(ports):
            ip = ips[n].strip()
            command =f'nc -w 1 -zvn {ip} {port} 1>/dev/null 2>/dev/null'
            output = os.system(command)
            time.sleep(0.8)
            if output == 0:
                PortRange.append("open")
            elif output == 256:
                PortRange.append("close")
        availibity.append(PortRange)
        n += 1
    n = 0
    dfs = []
    while n < len(ips):
        ip = ips[n].strip()
        dict = {"IP":ip,
        "FTP": availibity[n][0],
        "SSH":availibity[n][1],
        "DNS":availibity[n][2],
        "HTTP":availibity[n][3],
        "Kerberos":availibity[n][4],
        "SSL":availibity[n][5],
        "SMB":availibity[n][6],
        "MySQL":availibity[n][7],
        "WinRM":availibity[n][8],
        "WinRM":availibity[n][9],
        "HTTP 8080":availibity[n][10]}
        df = pd.DataFrame(dict,index=[0])
        dfs.append(df)
        n += 1
    df_test = pd.concat(dfs)
    return df_test.set_index('IP')

# Check args

if args.url:
    sub_df = subdomainScan(args.url)
    print(sub_df)
    if args.csv:
        csvExport(sub_df)
elif args.ip:
    df_ip = ipScan(args.ip)
    print(df_ip)
    if args.csv:
        csvExport(df_ip)

elif args.ports:
    df_port = portScan(args.ports)
    print(df_port)
    if args.csv:
        csvExport(df_port)
