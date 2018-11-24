#!/bin/bash
mn --custom mininet/custom/zgn-fattree.py --topo fattree --mac --arp --switch ovsk --controller=remote,ip=127.0.0.1,port=6633

