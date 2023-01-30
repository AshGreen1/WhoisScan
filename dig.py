#!/usr/bin/python3
import socket
import requests as req
import requests
import json

def checkISP(ip): # Ip to scan, type string
    ipinfo = f'https://ipinfo.io/{ip}'
    r = req.get(ipinfo)
    return json.loads(r.text)


def getIP(d):# Get the hostname with a subdomains, type string
    try:
        data = socket.gethostbyname(d)
        ISP = checkISP(data)
        return data
    except Exception:
        pass
