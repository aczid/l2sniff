Linux Ethernet Sniffer
======================

A simple Ethernet sniffer that can log the IP and MAC addresses for TCP, UDP, ICMP and ARP traffic.
It uses the Linux `PF_PACKET` interface to avoid relying on libpcap.

Building
--------

    $ make l2sniff

Running
-------

    $ sudo ./l2sniff eth0


References
----------

- [sniff-ipmac](https://github.com/vozlt/sniff-ipmac/)
- [PF_PACKET example](https://gist.github.com/cnlohr/c30db04f8d48f47eb80aaa13a83655d6)
