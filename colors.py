#!/usr/bin/python3

from colorama import Fore, Style

scolor = {"red":Fore.RED, "green": Fore.GREEN, "blue": Fore.BLUE,
    "yellow":Fore.YELLOW, "cyan":Fore.CYAN,"end":Style.RESET_ALL,
    "check": "[✓] ","asterisk": "[*] ","warning": "[!] ","none":""}

def colorize(data,color,symbol):
    return f"{scolor[color]} {scolor[symbol]}{data} {scolor['end']}"