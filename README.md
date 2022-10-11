# BugHunter Toolkit

This is a compilation of the automatic scanners that I have made for my work as a BugHunter.

In this case the WhoisScan is a scanner with four main functions to know the essentials of your target.

## Subdomain recognition

The first function is a basic scan to find subdomains without any API. 
In the future, I will improve the scanner to work with an API to find more subdomains (20% more from what I have seen).

## IP leakeage

The second function allow to proof a basic way to find IP leakeage in a server. Most of the time, the company just think in their principal domains
and they left the other domains (the domains used commonly for services like SAML or mailing) without any proxy, which allow a IP leakeage.

## ISP

This is a scanner to verify every IP obtained in the IP leakeage function. In the future the idea is use a API to get the ISP, but I wasn't able to make it work
yet.

## PORT scanner

This is a simple scanner to get the most common open ports on the targets I have seen. The idea is to look at each IP without being too noisy and leave less logging on the target.
With NMAP you can trigger a DDoS and you can get the IP blocked by mistake, but with this scanner it is unlikely.
