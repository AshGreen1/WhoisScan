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

def def_handler(sig, frame):
    print(Fore.RED,"\nKilling all the processes...\n",Style.RESET_ALL)
    sys.exit(1)

# Ctrl + C
signal.signal(signal.SIGINT, def_handler)

# Arguments
parser = argparse.ArgumentParser()
portHelp = "\tScan the common ports in a IP range (Need a file with the IPs)"
depthHelp = "\tDigging deeper into the subdomains (Need to be used with -u)"
ThreadHelp = "\tNumber of Threads to use "
ThreadHelp += "(default 20, only work in Ip Scan and Port Scan)"
#outHelp = "\tExport the scan as it is displayed"
csvHelp = "\tExport the scan as a CSV"
parser.add_argument("-u", "--url", help="\tThe url to scan")
parser.add_argument("-i", "--ip", help="\tA IP to scan")
parser.add_argument("-p", "--ports", help=portHelp)
parser.add_argument("-d", "--depth", help=depthHelp,action="store_true")
parser.add_argument("-t", "--threads", help=ThreadHelp,type=int)
#parser.add_argument("-oN", "--output", help=outHelp)
parser.add_argument("-c", "--csv", help=csvHelp,action="store_true")
args = parser.parse_args()
# End of Arguments

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
    # Check if depth is TRUE
    if args.depth:
        dig = depth(subdomainList)
        return dig
    else:
        row = f'{BS}Subdomains{BE}'
        df = pd.DataFrame({row:subdomainList})
        return df

# Scan the IP looking for a IP range
def ipScan(ip):
    ipSPrint = GS + ip + GE
    print(f'{pS} Analyzing IP {ipSPrint}')
    regex = '| grep "\b[0-9]*. - [0-9]*.*\B[0-9]" '
    regex += '| awk -F ":" "{print $2}" | sed "s/ //g"'
    command = f'whois {ip}'
    output = commandLine(command).replace("\n","")
    pattern_range = r'\d+\.\d+\.\d+\.\d+/\d\d'
    output = re.findall(pattern_range, output)
    ipRangeFound = GS + output[0] + GE
    print(f'{cS} The Ip range {ipRangeFound} was found!')
    # The script for the Threads was took from here:
    # https://gist.github.com/sourceperl/10288663
    # Thanks @spongi for  showing me this wonderful script! :D
    ips_q = queue.Queue()
    out_q = queue.Queue()
    init = time.time()
    if args.threads:
        num_threads = args.threads
    else:
        num_threads = 20
    ips = []
    for ip in ipaddress.IPv4Network(output[0]):
        ips.append(format(ip))
    def pingerIps(i,q):
        while True:
            ip = q.get()
            args=['/bin/ping','-c','1','-W','1',str(ip)]
            p_ping = subprocess.Popen(args,
                                      shell=False,
                                      stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL)
            p_ping_out = str(p_ping.communicate()[0])
            if (p_ping.wait() == 0):
                out_q.put(str(ip))
                print(f'{cS} {GS}{ip}{GE} is Active!')
            q.task_done()
    for i in range(num_threads):
        worker = Thread(target=pingerIps, args=(i, ips_q),daemon=True)
        worker.start()
    for ip in ips:
        ips_q.put(ip)
    ips_q.join()
    active = []
    while True:
        try:
            msg = out_q.get_nowait()
        except queue.Empty:
            break
        active.append(msg)
    return active
# Scanning Ports from IP file or Ip

def portScan(ipsArg):
    print(pS,"Checking most common ports...")
    ips_q = queue.Queue()
    open_q = queue.Queue()
    close_q = queue.Queue()
    init = time.time()
    if args.threads:
        num_threads = args.threads
    else:
        num_threads = 20
    ls_args=['/bin/ls',ipsArg]
    ls = subprocess.Popen(ls_args,
                          shell=False,
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)
    if (ls.wait() == 0):
        ips = list(open(ipsArg))
    elif (ls.wait() == 2):
        print(f'{wS} {YS}This is not a Ip file')
        prompt = f'{wS}{YS} Do you want make a IpScan first?\n{wS} {YS}Y/N: '
        choose = input(prompt)
        if choose.strip() == "y" or choose.strip() == "Y":
            ips = ipScan(args.ports)
        else:
            ips = ipsArg
# Function to scan ports
    def Scanning(i,q):
        while True:
            ports = [21,22,53,80,88,443,445,3306,3389,5985,5986,8080]
            ip = q.get()
            for x in ports:
                args=['/bin/nc','-w','1','-zvn',str(ip).strip(),str(x).strip()]
                p_nc = subprocess.Popen(args,
                                          shell=False,
                                          stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL)
                if (p_nc.wait() == 0):
                    open_q.put(str(ip)+":"+str(x))
                else:
                    close_q.put(str(ip)+":"+str(x))
            q.task_done()
# Start the Threads
    for i in range(num_threads):
        worker = Thread(target=Scanning, args=(i, ips_q),daemon=True)
        worker.start()
    sanitized_ips = []
    for ip in ips:
        ips_q.put(ip.strip())
        sanitized_ips.append(ip.strip())
    ips_q.join()
    open_ports = []
    close_ports = []
    while True:
        try:
            msg = open_q.get_nowait()
            msg2 = close_q.get_nowait()
        except queue.Empty:
            break
        open_ports.append(msg)
        close_ports.append(msg2)
    print(cS,GS,"Complete!",GE)
# Filtering the results from Scanning
    ips_ports_open = []
    ips_ports_close = []
    for ip in sanitized_ips:
        port_array_open = []
        for x in open_ports:
            ip_port = x.split(":")
            if ip == ip_port[0]:
                port_array_open.append(f"Open:{ip_port[1]}")
            else:
                continue
        port_array_close = []
        for x in close_ports:
            ip_port = x.split(":")
            if ip == ip_port[0]:
                port_array_close.append(f"Close:{ip_port[1]}")
            else:
                continue
        ips_ports_open.append(port_array_open)
        ips_ports_close.append(port_array_close)
# DataFrame Maker
    def dfMaker(ports_open,ports_close,ips):
        # Open
        n = 0
        dict = {}
        for x in ports_open:
            dict_open = {}
            for i in x:
                open = i.split(":")
                port = f'{BS}{open[1]}{BE}'
                dict_open[port] = f'{GS}{open[0]}{GE}'
            dict[ips[n]] = dict_open
            n += 1
        # Close
        n = 0
        dict2 = {}
        for x in ports_close:
            dict_close = {}
            for i in x:
                close = i.split(":")
                port = f'{BS}{close[1]}{BE}'
                dict_close[port] = f'{RS}{close[0]}{RE}'
            dict2[ips[n]] = dict_close
            n += 1
        df_close = pd.DataFrame.from_dict(dict2).fillna(f"{RS}Close{RE}")
        df_open = pd.DataFrame.from_dict(dict).fillna(f"{RS}Close{RE}")

        frames = [df_open,df_close]

        return pd.concat(frames).transpose()
    return dfMaker(ips_ports_open,ips_ports_close,sanitized_ips)

# Check args

if args.url:
    sub_df = subdomainScan(args.url)
    print(sub_df)
    if args.csv:
        csvExport(sub_df)
elif args.ip:
    df_ip = ipScan(args.ip)
    df_ips_active = pd.DataFrame({"Active":df_ip}).transpose()
    print(df_ips_active)
    if args.csv:
        csvExport(df_ip)

elif args.ports:
    df_port = portScan(args.ports)
    #pdb.set_trace()
    print(df_port.T.drop_duplicates().T.sort_index(axis=1))
    if args.csv:
        csvExport(df_port)
