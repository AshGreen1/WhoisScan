#!/usr/bin/python3

from command import *
from colors import *

def ComplementInstaller():
    apt = commandLine.normal(f'sudo apt-get update && sudo apt-get upgrade')
    complements = ["netcat","nc","dig"]
    for i in complements:
        commandLine.normal(f"sudo apt-get install {i}")
    modules = ["subprocess","sys","tqdm","pandas","re","requests","html2text","os","time","pwntools"]
    for i in modules:
        commandLine.normal(f"pip install {i}")
    # Taking the path for WhoisScan
    pwd = commandLine.normal(f'pwd').strip() + "/WhoisScan.py"
    chmod = commandLine.normal(f'/usr/bin/chmod +x ./WhoisScan.py')
    ln = commandLine.normal(f'sudo ln -s {pwd} /usr/bin/WhoisScan')
    print(colorize('Symbolic link to WhoisScan created! Now you can type "WhoisScan" on your shell to execute the tool','green','check'))


ComplementInstaller()
