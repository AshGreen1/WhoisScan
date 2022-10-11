#!/usr/bin/python3

import os

print("You must run this script as root")

def ComplementInstaller():
    complements = ["netcat","nc","dig"]
    for i in complements:
        os.system("apt install " + i)
    modules = ["subprocess","sys","tqdm","pandas","re","requests","html2text","os","time"]
    for i in modules:
        os.system("pip install " + i)

ComplementInstaller()
