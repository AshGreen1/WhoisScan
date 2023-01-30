#!/usr/bin/python3
import requests as req
from colors import *
from bs4 import BeautifulSoup
from pwn import *
import re
import socket
import dig
import threading
import time
import html2text
import queue
import pdb
import random
from counter import *

def permutation(word,base,here,p0): # wordlist,base domain and list to append
    p0.status('Checking...')
    for i in word:
        if re.search(r"/-$/",str(i)):
            i = i.replace("-",".")
            here.append(f'{i}.{base}')
        else:
            here.append(f'{i}.{base}')

def looping(num,array,to_apend,state,n): # type: int, list, empty list and progress
    time.sleep(0.1)
    num_threads = 100
    subs_q = queue.Queue()
    out_q = queue.Queue()
    def loop(num,array,to_apend,state,n,q):
        while True:
            subs = q.get()
            state.status(f'{n.value()+1}')
            try:
                ip = dig.getIP(array[n.value()]) # wordlists
                if ip != None:
                    out_q.put(subs)
                    to_apend.append(array[n.value()])
            except:
                pass
            n.increment()
            q.task_done()

    for i in range(num_threads):
        worker = threading.Thread(target=loop, args=(num,array,to_apend,state,n,subs_q,))
        worker.setDaemon(True)
        worker.start()

    for sub in array:
        subs_q.put(sub)
    
    subs_q.join()

    while True:
        try:
            msg = out_q.get_nowait()
            to_apend.append(msg)
        except queue.Empty:
            break
    state.success(colorize('Complete!','green','check'))

def genWord(list_clean,domain): # wordlist and domain
    # Generating wordlists
    print(colorize("Generating wordlists...",'blue','asterisk'))
    words = []
    for n in list_clean:
        n = n.split(".")
        for x in n:
            words.append(x)
    words = set(words)

    # Cleaning the wordlists
    clean_words = []
    for word in words:
        domain_split = domain.split(".")
        if word == domain_split[0] or domain_split[1] == word:
            continue
        elif re.search(r'/\*/',word):
            continue
        else:
            clean_words.append(word)

    # Permuting the wordlists
    p0 = log.progress(colorize('Checking subdomains generated, please, wait a moment...','blue','none'))
    wordlists = []
    thread1 = threading.Thread(target=permutation, args=(clean_words,domain,wordlists,p0,), daemon=True)
    thread1.start()
    thread1.join()
    subdomains = []
    for sub in wordlists:
        thread2 = threading.Thread(target=permutation, args=(clean_words,sub,subdomains,p0,), daemon=True)
        thread2.start()
        thread2.join()
    p0.success(colorize('Analysis complete!','green','check'))
    data = []

    # Checking the subdomains to see which revolve
    p1 = log.progress(colorize(f'Analyzing the first {len(wordlists)} subdomains','blue','none'))
    n = ThreadSafeCounter()
    looping(len(wordlists),wordlists,data,p1,n)
    p2 = log.progress(colorize(f'Analyzing the second {len(subdomains)} subdomains','blue','none'))
    n = ThreadSafeCounter()
    looping(len(subdomains),subdomains,data,p2,n)
    p3 = log.progress(colorize(f'Analyzing the last {len(list_clean)} subdomains','blue','none'))
    n = ThreadSafeCounter()
    looping(len(list_clean),list_clean,data,p3,n)
    data2 = []
    domain = r"\." + domain + r"$"
    for i in data:
        if i not in data2:
            if re.search(domain,i):
                data2.append(i)
    p4 = log.progress(colorize("Finishing threads",'blue','none'))
    p4.success(colorize('Scan complete!','green','check'))
    return data2

def ISPprovider(ips): # list ips
    for i in ips:
        r = req.get(f'https://www.whatismyisp.com/ip/{i}')
        response = html2text.html2text(r.text)
        pattern = r'The ISP of IP\D\d+.\d+.\d+.\d+\D+'
        match = re.findall(pattern,response)
        provider = match[0].split("\n")[0]
        pattern2 = r'\d+.\d+.\d+.\d+\D+'
        match2 = re.findall(pattern2,provider)
        realProvider = match2[0].split(" ")[2]
        return realProvider

def subdomainScan(domain): # domain passed to the function
    def crt(domain):
        print(colorize("Starting subdomain search...",'blue','asterisk'))
        url = f'https://crt.sh/?q={domain}'
        user_agent = open("user-agents").read().split("\n")
        user_agent = {"User-Agent":random.choice(user_agent)}
        r = req.get(url, headers=user_agent)
        if r.status_code == 429:
            raise Exception("Too many request, try using a proxy or a VPN!")
        elif r.status_code == 200:
            print(colorize('First list of subdomains generated!','green','check'))
        else:
            raise Exception(f"{r.status_code} found!")
        soup = BeautifulSoup(r.text, 'html.parser')
        list_sub = []

        # Filtering subdomains
        for td in soup.find_all('td'):
            match = re.findall(r'<td>(.*?)<\/td>',str(td))
            try:
                if re.search(domain,match[0]):
                    if re.search("<br/>", match[0]):
                        match = match[0].split("<br/>")
                        for i in len(match):
                            list_sub.append(i)
                    list_sub.append(match[0])
                else:
                    pass
            except:
                pass
        list_sub = set(list_sub)
        list_clean = []

        # Cleaning subdomains
        for i in list_sub:
            if re.search("--",i) and re.search("---",i):
                list_clean.append(i.replace("--",""))
            elif re.search("--",i) and not re.search("---",i):
                list_clean.append(i.replace("--","-"))
            else:
                list_clean.append(i)
        return list_clean
    list_clean = crt(domain)
    n = 0

    # Handling possible Behaviors
    while (bool(list_clean) == False):
        print(colorize('Something went wrong, trying again...','red','warning'))
        list_clean = crt(domain)
        n += 1
        if n >= 5:
            break
    if bool(list_clean) == True:
        wordlists = genWord(list_clean,domain)
        print(colorize("Subdomain search finished!","green","check"))
        return wordlists
    else:
        raise Exception("Could not get any subdomain")
