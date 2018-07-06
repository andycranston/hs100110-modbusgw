# TP-Link HS100 and HS110 Mosbus Gateway

Python code to implement a Modbus gateway to allow SCADA (Supervisory
Control and Data Aquisition) systems to read the on/off status of TP-Link
HS100 and HS110 Smart Wifi Plugs.  Also allows these systems to switch
the plugs on and off under their own control.

## Production Ready?

Not yet.

Needs plenty of error checking to get it more bullet proof.

## The programs

* `modbusgwudp.py` - uses Modbus over UDP
* `modbusgwtcp.py` - uses Modbus over TCP

The UDP client will not get any future work.

However, the TCP version is lined up for more development.

## Running the progams

Copy the Python programs to a directory on your UNIX/Linux
system.  Change to that directory.  Determine the IP address
of your UNIX/Linux system.  Typing one of:

```
ifconfig -a
ip addr
```

Should provide the details you need.  For the examples here I will
assume ths IP address is:

```
192.168.1.13
```

Next determine the IP address of one of your TP-Link HS100 or HS110
plugs.  For the examples here I will use:

```
192.168.1.65
```

Next choose a TCP/IP port that the programs will bind to.  Modbus usually
runs over TCP/IP port 502 but I advise using a higher numbered port
to ensure you will not have an issue trying to use a port your operating system has reserverd (typically port numbers below 4096 are reserved for
programs that run with `root` priviledges).  In the examples
below I will use this port number:

```
8502
```

To run the gateway using Modbus over UDP type:

```
python mosbusgwudp --ipaddr 192.168.1.65 --port 8502
```

Similarly to run the gateway using Modbus over TCP type:

```
python mosbusgwudp --ipaddr 192.168.1.65 --port 8502
```

## Configure your SCADA system to talk to the gateway

The details for the HS100/HS110 plug as far as your SCADA system
is concerned is:

```
Type ..............: Modbus
Protocol ..........: TCP or UDP
IP address ........: 192.168.1.13
Port ..............: 8502
Unit ID ...........: 1
Register type .....: Read/Write Coil Status (FC01/FC05)
Register number ...: 0
Length/count ......: 1
```

## To do list

Here are things still left to do:

* Make the code far more robust to errors
* Add an option to alter amount of debug output
* Add an option to send debug output to a file instead of the terminal
* Provide a way to run the code a background daemon process

## Useful links

Some useful links that helped with the development of this code - a big
thank you from me to all concerned:

[xxx](https://www.softscheck.com/en/reverse-engineering-tp-link-hs110/)
[xxx](https://github.com/softScheck/tplink-smartplug)
[xxx](https://github.com/softScheck/tplink-smartplug/blob/master/tplink-smartplug.py)
[xxx](https://unserver.xyz/modbus-guide/)
[xxx](https://www.binarytides.com/python-socket-programming-tutorial/)
[xxx](https://pymotw.com/3/threading/)

-----------------------------------------------
