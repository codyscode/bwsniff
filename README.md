# bwsniff
Bwsniff is a packet sniffing based network bandwidth monitor that runs on Linux.
Most bandwidth monitors are either limited to the host they're running on or 
require some administrative access to monitor the whole network. Bwsniff only
requires that packets be visible to your NIC.

# Setup
1. Install libpcap: sudo apt-get install libpcap-dev
2. Install ncurses: sudo apt-get install libncurses-dev
3. cd into bwsniff folder and run: make
4. Run program with: sudo ./bwsniff

# Screenshots
![Setup Screen](https://i.imgur.com/ynmOwjQ.png "Setup Screen")
![Main Screen Filtered](https://i.imgur.com/xtnfwtK.png "Main Screen Filtered")
![Main Screen Unfiltered](https://i.imgur.com/bdP6gwj.png "Main Screen Unfiltered")

# Limitations
Bwsniff has the same limitations as other packet sniffers. WiFi monitoring is
pretty straight forward but to monitor a switched Ethernet network you'd have
to take some extra steps to ensure all packets are visible to your NIC.

# Side Notes
This is still in its early stages. Currently it only uses the data link layer of
the network but I might add some network layer functionality at some point. I
used ncurses to simplify making the UI but it's very minimal right now. I haven't
done any cleanup or garbage collection yet since the only way to exit the program 
is Ctrl+C.
