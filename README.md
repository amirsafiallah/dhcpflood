DHCP Flood C++ Source
=====================
This source code uses [libtins](https://libtins.github.io/) to manipulate
DHCP packets. Creates a DHCP Request of all IP pool range and broadcasts.
This is a simple source code just for educational purposes.

How It Works
------------

- It picks an IP address from the specified IP pool range
- Generates a random MAC
- Creates a DHCP Request packet with that IP and random MAC
- Broadcasts
- Waits for receiving ACK/NACK from DHCP Server
- Picks the next IP address from the ip range and repeats steps again.

The steps explained above, causes an starvation in DHCP IP assignment.
So DHCP won't work any more.

Warning
-------
This source code was written for educational purposes and run under controlled conditions,
It may cause network problems, Use it on your own risk.

How to compile
--------------
- Compile and install [libtins](https://libtins.github.io/)
- Run the following commands on the `DHCP Flood` directory:

        mkdir build
        cmake ..
        make

Note that you may need root privilege to send packets.

Licenses
--------

libtins (packet crafting and sniffing library)
- https://libtins.github.io/