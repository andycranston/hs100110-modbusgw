# TP-Link HS100 and HS110 Mosbus Gateway

Python code to implement a Modbus gateway to allow SCADA (Supervisory
Control and Data Aquisition) systems to read the on/off status of TP-Link
HS100 and HS110 Smart Wifi Plugs.  Also allows these systems to switch
the plugs on and off under their own control.

# Production Ready?

Not yet.

Needs plenty of error checking to get it more bullet proof.

# The programs

> `modbusgwudp.py` - uses Modbus over UDP
> `modbusgwtcp.py` - uses Modbus over TCP

The UDP client will not get any future work.

However, the TCP version is lined up for more development.

-----------------
