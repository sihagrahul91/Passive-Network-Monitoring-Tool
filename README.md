Passive Network Monitoring Tool

Author:
-------
Rahul Sihag
http://www3.cs.stonybrook.edu/~rsihag/

How to use:
-----------
./mydump [-i interface] [-r file] [-s string] expression

-i  Live capture from the network device <interface> (e.g., eth0). If not
    specified, mydump will automatically select a default interface. It will
    capture continuously until the user terminates the program.

-r  Read packets from <file> in tcpdump format.

-s  Keep only packets that contain <string> in their payload (after any BPF
    filter is applied).

expression = BPF Filer

Compile & Run:
--------------
1. The program contains three files - myStruct.h(header file), mydump.c(source file) and a Makefile
2. Use make to compile the program and make clean to delete the executables. 

Implementation:
---------------
Offline and Online modes are determined using the options given by the user. pcap_open_live and pcap_open_offline APIs are used for capturing the packets. BPF filter is compiled & applied and payload filter is passed to the callback function. ICMP, TCP, UDP, ARP and other packets are printed along with the ethernet header and payload.
Sufficient comments have been added in the code to explain the functionality.

Testing:
--------
Code has been tested thoroughly. No bugs have been found.

References:
-----------
1. http://unix.superglobalmegacorp.com/Net2/newsrc/netinet/if_ether.h.html
2. https://stackoverflow.com
