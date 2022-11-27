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
#import threading
import colorama
from colorama import Fore, Style
import pdb

cS = Fore.GREEN + "[✓]" + Style.RESET_ALL
pS = Fore.CYAN + "[*]"  + Style.RESET_ALL

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
def ipRangeToScan(ip,l):
    device = []
    #x = threading.Thread()
    if l == 1:
        warning = Fore.YELLOW + "[!] This analysis will take about 5 minutes"
        print(warning + Style.RESET_ALL,end="\n")
        print("Checking for devices availables...",end="\n")
        def n(ip):
            for i in tqdm(range(0,255)):
                #print(x,flush=True)
                command = f"ping -c 1 -w 1 {ip}.{str(i)} | grep 'ttl'"
                output = commandLine(command)
                pattern = r'\d+\.\d+\.\d+\.\d+'
                match = re.findall(pattern,output)
                if bool(match) != False:
                    device.append(match[0])
        #x = threading.Thread(target=n,args=(ip,))
        #x.start()
        n(ip)
    elif l == 2:
        warning = Fore.YELLOW + "[!] This analysis will take about 18 hours"
        print(warning, end="\n")
        print(f'Are you sure about this scan?{Style.RESET_ALL}',end="\n")
        choose = input("yes/no: ")
        if choose == "yes":
            print("Checking for devices availables...",end="\n")
            def z(ip):
                for i in range(0,255):
                    print("Analyzing " + ip + "." + str(i) + ".0")
                    for x in tqdm(range(0,255)):
                        scanning = ip + "." + str(i) + "." + str(x)
                        command = f'ping -c 1 -w 1 {scanning} | grep "ttl"'
                        output = commandLine(command)
                        pattern = r'\d+\.\d+\.\d+\.\d+'
                        match = re.findall(pattern,output)
                        if bool(match) != False:
                            device.append(match[0])
            #x = threading.Thread(target=z,args=(ip,))
            #x.start()
            z(ip)
        else:
            print(f'{Fore.RED}[!] Scan aborted!{Style.RESET_ALL}', end="\n")
    return device
## Scan the IP looking for a IP range
def ipScan(ip):
    ipSPrint = Fore.GREEN + ip + Style.RESET_ALL
    print(f'Analyzing IP {ipSPrint}')
    regex = '| grep "\b[0-9]*. - [0-9]*.*\B[0-9]" '
    regex += '| awk -F ":" "{print $2}" | sed "s/ //g"'
    print(regex)
    command = f'whois {ip}'
    output = commandLine(command).replace("\n","")
    pattern_range = r'\d+\.\d+\.\d+\.\d+ - \d+\.\d+\.\d+\.\d+'
    output = re.findall(pattern_range, output)
    ipRange = []
    for i in range(0,1):
        pattern = r'\d+\.\d+\.\d+\.\d+'
        ipRange.append(re.findall(pattern,output[i])[0])
        ipRange.append(re.findall(pattern,output[i])[1])
    ipPrint = f'{Fore.GREEN}{ipRange[0]} - {ipRange[1]}{Style.RESET_ALL}'
    print(cS, "IP range", ipPrint, "found!")
    howMany = ipRange[0].split(".")
    howMany2 = ipRange[1].split(".")
    ipResult = []
    ipOrigin = []
    for i in range(0,4):
        print("valor de i ",i)
        ipResult.append(int(howMany2[i])-int(howMany[i]))
        ipOrigin.append(int(howMany[i]))
        #pdb.set_trace()
    print(ipResult,ipOrigin)
    ipGenerated = []
    n = 0
    #for x in ipOrigin:
    pdb.set_trace()

    egIp = f'{ipOrigin[0]}{ipOrigin[1]}{ipOrigin[2]}{ipOrigin[3]}'
    print(egIp)
        #if ipResult[n] == 0:
        #    ipGenerated.append(x)
        #elif ipResult[n] != 0 and ipResult[n+1] != 0:
        #    ipGenerated.append(x+1)
        #elif ipResult[n+1]-ipOrigin[]:
        #    ipGenerated.append(x+1)
        #print(ipGenerated,n)
        #print(ipOrigin)
            #if n < 3:
    n += 1
            #else:
            #    n = 0

        #print(ipOrigin[n]+ipResult[n])
        #ipRange = []
        #for i in range(1,ipResult[n]):
        #    if (ipOrigin[n]+i+1) == ipResult[n]:
        #        print(True)
        #    elif (ipOrigin[n]+i+1) != ipResult[n]:
        #        print("")
    #if 255-int(howMany[2]) == 255 and 255-int(howMany[3]) == 255:
    #    toScan = f'{howMany[0]}.{howMany[1]}'
    #    long = 2
    #    rangeIp = ipRangeToScan(toScan,long)
    #elif 255-int(howMany[2]) != 255 and 255-int(howMany[3]) == 255:
    #    toScan = f'{howMany[0]}.{howMany[1]}.{howMany[2]}'
    #    long = 1
    #    rangeIp = ipRangeToScan(toScan,long)
    #return rangeIp

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
