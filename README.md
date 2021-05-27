# Simple DNS-server
Simple DNS-server (53/UDP) in Python 3 using dnslib and dnspython.

## Deps
Install dnslib, dnspython and treelib:  
`sudo pip3 install dnslib dnspython treelib`

## Use
In one terminal tab enter `sudo python3 main.py`.  
In another create a DNS-queries using dig: `dig <domain> @127.0.0.1`.  
