#!/usr/bin/python3
import subprocess
import sys
import pandas as pd
import re
import os
import time
import argparse
import signal
from threading import Thread
from colorama import Fore, Style
import ipaddress
import queue
import scan
from colors import *
import dig
from command import *
from pwn import *
import counter
# CTRL + C
commandLine.ctrl_c()

# Arguments
parser = argparse.ArgumentParser(add_help=False)
portHelp = "\tScan the common ports in a IP range (Need a file with the IPs)"
depthHelp = "\tDigging deeper into the subdomains (Need to be used with -u)"
ThreadHelp = "\tNumber of Threads to use "
ThreadHelp += "(default 20, only work in Ip Scan and Port Scan)"
csvHelp = "\tExport the scan as a CSV"
jsonHelp = "\tExport the scan as a JSON"
parser.add_argument("-u", "--url", help="\tThe url to scan")
parser.add_argument("-i", "--ip", help="\tA IP to scan")
parser.add_argument("-p", "--ports", help=portHelp)
parser.add_argument("-d", "--depth", help=depthHelp,action="store_true")
parser.add_argument("-t", "--threads", help=ThreadHelp,type=int)
parser.add_argument("-c", "--csv", help=csvHelp,action="store_true")
parser.add_argument("-j", "--json", help=jsonHelp,action="store_true")
parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                    help='Show this help message and exit.')
args = parser.parse_args()
# End of Arguments

# Export DataFrame as csv

class export():

    # Export to CVS
    def csv(data):
        os.makedirs('scanned/', exist_ok=True)
        now = time.localtime()
        timeNow = time.strftime("%m-%d-%Y-%H-%M-%S", now)
        data.to_csv(f"scanned/dataFrame-{timeNow}.csv")

    # Export to JSON
    def json(data):
        os.makedirs('scanned/', exist_ok=True)
        now = time.localtime()
        timeNow = time.strftime("%m-%d-%Y-%H-%M-%S", now)
        data.to_json(f"scanned/dataFrame-{timeNow}.json")

# Check if empty

def empty(data,where):
    if data != None:
        where.append(data)

# Scan the IP looking for a IP range
def ipScan(ip):
    ipSPrint = str(colorize(ip,'green','none'))
    log.info(colorize(f'Analyzing IP {ipSPrint}','blue','none'))
    commands = f'whois {ip}'
    output = commandLine.normal(commands)
    pattern_range = r'\d*?\.\d*?\.\d*?\.\d*?\/\d*?\n'
    output = re.findall(pattern_range, output)[0].strip()
    ipRangeFound = colorize(output,'green','none')
    log.info(colorize(f'Found Ip range {ipRangeFound}','blue','none'))

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
    n = 0
    for ip in ipaddress.IPv4Network(output):
        ips.append(format(ip))
        n += 1
    p = log.progress(colorize(f'{n} Possibles IPs','blue','none'))
    c = counter.ThreadSafeCounter()
    # Looking for devices

    def pingerIps(i,q,c,p):
        while True:
            p.status(f'{c.value()}')
            ip = q.get()
            args=['/bin/ping','-c','1','-W','1',str(ip)]
            p_ping = commandLine.status(args)
            if (p_ping == 0):
                out_q.put(str(ip))
                print(colorize(f'{ip} is Active!','green','check'))
            c.increment()
            q.task_done()
    
    # Starting threads

    for i in range(num_threads):
        worker = Thread(target=pingerIps, args=(i, ips_q,c,p),daemon=True)
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
    p.success(colorize("Complete!",'green','none'))
    return active

# Scanning Ports from IP file or Ip

def portScan(ipsArg):
    p = log.progress(colorize("Checking most common ports...",'blue','none'))
    ips_q = queue.Queue()
    open_q = queue.Queue()
    close_q = queue.Queue()
    c = counter.ThreadSafeCounter()
    init = time.time()
    if args.threads:
        num_threads = args.threads
    else:
        num_threads = 20
    ls_args=['/bin/ls',ipsArg]
    ls = commandLine.status(ls_args)
    if (ls == 0):
        ips = list(open(ipsArg))
    elif (ls > 0):
        print(colorize(f'This is not a Ip file','yellow','warning'))
        prompt = colorize(f'Do you want make a IpScan first? Y/N: ','yellow','warning')
        choose = input(prompt)
        if choose.strip() == "y" or choose.strip() == "Y":
            ips = ipScan(args.ports)
        else:
            ips = ipsArg

# Function to scan ports
    def Scanning(i,q,c,p):
        while True:
            p.status(f'{c.value()}')
            ports = [21,22,53,80,88,443,445,3306,3389,5985,5986,8080]
            ip = q.get()
            for x in ports:
                args=['/bin/nc','-w','1','-zvn',str(ip),str(x)]
                p_nc = commandLine.status(args)
                if (p_nc == 0):
                    open_q.put(str(ip)+":"+str(x))
                else:
                    close_q.put(str(ip)+":"+str(x))
            c.increment()
            q.task_done()

# Start the Threads
    for i in range(num_threads):
        worker = Thread(target=Scanning, args=(i, ips_q,c,p),daemon=True)
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
                port = colorize(f'{open[1]}','blue','none')
                dict_open[port] = colorize(f'{open[0]}','green','none')
            dict[ips[n]] = dict_open
            n += 1
        # Close
        n = 0
        dict2 = {}
        for x in ports_close:
            dict_close = {}
            for i in x:
                close = i.split(":")
                port = colorize(f'{close[1]}','blue','none')
                dict_close[port] = colorize(f'{close[0]}','red','none')
            dict2[ips[n]] = dict_close
            n += 1
        df_close = pd.DataFrame.from_dict(dict2).fillna(colorize("Close",'red','none'))
        df_open = pd.DataFrame.from_dict(dict).fillna(colorize("Close",'red','none'))

        frames = [df_open,df_close]

        return pd.concat(frames).transpose()
    final_df = dfMaker(ips_ports_open,ips_ports_close,sanitized_ips)
    p.success(colorize("Complete!",'green','none'))
    return final_df

# Check args
if __name__ == "__main__":

    # Subdomains and IPs
    if args.url and args.depth:
        sub_df = scan.subdomainScan(args.url)
        ips = []
        print(colorize('Creating DataFrame...','cyan','asterisk'))
        for i in sub_df:
            ips.append(dig.getIP(i))
        ip_clean = []
        for i in ips:
            empty(i,ip_clean)
        isp = scan.ISPprovider(ip_clean)
        df = pd.DataFrame({"Subdomains":sub_df,"IPs":ips, "ISP":isp})
        df.index += 1
        print(df)
        if args.csv:
            export.csv(df)
        elif args.json:
            export.json(df)

    # Subdomains
    elif args.url:
        sub_df = list(dict.fromkeys(scan.subdomainScan(args.url)))
        df = pd.DataFrame({"Subdomains":sub_df})
        df.index += 1
        print(df)
        if args.csv:
            export.csv(df)
        elif args.json:
            export.json(df)

    # IP range scan
    elif args.ip:
        df_ip = ipScan(args.ip)
        df_ips_active = pd.DataFrame({"Active":df_ip}).transpose()
        print(df_ips_active)
        if args.csv:
            export.csv(df_ips_active)
        elif args.json:
            export.json(df_ips_active)

    # Basic port scan
    elif args.ports:
        df_port = portScan(args.ports)
        print(df_port.T.drop_duplicates().T.sort_index(axis=1))
        if args.csv:
            export.csv(df_port)
        elif args.json:
            export.json(df_port)
    else:
        print(parser.format_help())
