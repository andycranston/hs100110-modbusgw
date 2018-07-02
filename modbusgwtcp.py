#! /usr/bin/python3
#
# @(!--#) @(#) modbusgwtcp.py, version 004, 02-july-2018
#
# modbus gateway over TCP for a TP-Link HS100/HS110 Smart WiFi Plug
#
# Links
#
#    https://www.softscheck.com/en/reverse-engineering-tp-link-hs110/
#    https://github.com/softScheck/tplink-smartplug
#    https://github.com/softScheck/tplink-smartplug/blob/master/tplink-smartplug.py
#    https://unserver.xyz/modbus-guide/
#    https://www.binarytides.com/python-socket-programming-tutorial/
#

#
# imports
#

import sys
import os
import argparse
import socket
import threading

########################################################################

DEFAULT_MODBUS_PORT = "8502"

MAX_PACKET_LENGTH = 1024
MAX_TCP_PACKET_LENGTH = 1024

GETSYSINFO =  '{"system":{"get_sysinfo":{}}}'
SETRELAYON  = '{"system":{"set_relay_state":{"state":1}}}'
SETRELAYOFF = '{"system":{"set_relay_state":{"state":0}}}'

########################################################################

def showpacket(bytes):
    bpr = 16              # bpr is Bytes Per Row
    numbytes = len(bytes)

    if numbytes == 0:
        print("<empty frame>")
    else:
        i = 0
        while i < numbytes:
            if (i % bpr) == 0:
                print("{:04d} :".format(i), sep='', end='')

            print(" {:02X}".format(bytes[i]), sep='', end='')

            if ((i + 1) % bpr) == 0:
                print()

            i = i + 1

    if (numbytes % bpr) != 0:
        print()
        
    return

########################################################################

def encrypt(barray):
    key = 171
    result = bytearray(len(barray) + 4)
    i = 4
    for b in barray:
        a = key ^ b
        key = a
        result[i] = a
        i += 1
    return result

########################################################################

def decrypt(barray):
    key = 171 
    result = bytearray(len(barray))
    i = 0
    for b in barray: 
        a = key ^ b
        key = b 
        result[i] = a
        i += 1
    return result

########################################################################

def runplugcommand(ipaddr, command):
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    tcp.connect((ipaddr, 9999))

    tcp.send(encrypt(bytearray(command, 'utf-8')))

    plugdata = tcp.recv(MAX_PACKET_LENGTH)

    tcp.close()

    return(decrypt(plugdata[4:]))

########################################################################

def getrelaystatus(ipaddr):
    sysinfo = runplugcommand(ipaddr, '{"system":{"get_sysinfo":{}}}')

    if bytearray('","relay_state":0,', 'utf-8') in sysinfo:
        return 0
    elif bytearray('","relay_state":1,', 'utf-8') in sysinfo:
        return 1
    else:
        return None

########################################################################

def setrelaystatus(ipaddr, status):
    if status == 0:
        cmd = SETRELAYOFF
    else:
        cmd = SETRELAYON

    errcode = runplugcommand(ipaddr, cmd)

########################################################################

def handleconnection(conn):
    while True:
        inpacket = bytearray(1024)

        i = 0

        while (i < 6):
            b = conn.recv(6 - i)

            bcount = len(b)

            if bcount == 0:
                print("{}: socket has closed".format(progname))
                return

            inpacket[i:i+(bcount - 1)] = b

            i += bcount

        print("Read Modbus header i={}".format(i))

        if (i != 6):
            print("{}: read of first 6 bytes of Modbus TCP packet has not worked - ignoring".format(progname), file=sys.stderr)
            showpacket(inpacket[0:(i-1)])
            continue

        packetlength = (inpacket[4] * 256) + inpacket[5]

        if (packetlength < 2):
            print("{}: Modbus TCP packet length too short to have any useful data in it - ignoring".format(progname), file=sys.stderr)
            showpacket(inpacket[0:5])
            continue

        i = 0

        while (i < packetlength):
            b = conn.recv(packetlength - i)

            bcount = len(b)

            if bcount == 0:
                print("{}: socket has closed".format(progname))
                return

            inpacket[6+i:6+i+(bcount - 1)] = b

            i += bcount

        print("Read Modbus data i={}".format(i))

        if (i != packetlength):
            print("{}: read of first {} data bytes in Modbus TCP packet has not worked - ignoring".format(progname, packetlength), file=sys.stderr)
            showpacket(inpacket[0:6+(i-1)])
            continue

        unitid = inpacket[6]
    
        if unitid != 1:
            print("{}: this gateway only serves Modbus UDP packets with Unit ID of 1 - ignoring".format(progname), file=sys.stderr)
            showpacket(inpacket[0:31])
            continue

        functioncode = inpacket[7]

        if functioncode == 1:
            # read coil
            print("Function code 0x01 - read single coil")
            showpacket(inpacket[0:31])

            if packetlength != 6:
                print("{}: incorrect packet length for function code 0x01 - ignoring".format(progname), file=sys.stderr)
                continue

            addr = (inpacket[8] * 256) + inpacket[9]

            if (addr != 0):
                print("{}: this gateway only serves Modbus UDP packets with address of 0 - ignoring".format(progname), file=sys.stderr)
                continue

            numr = (inpacket[10] * 256) + inpacket[11]

            if (numr != 1):
                print("{}: this gateway only serves Modbus UDP packets with register count of 1 - ignoring".format(progname), file=sys.stderr)
                continue

            relay = getrelaystatus(ipaddr)

            response = bytearray(6 + 4)

            response[0:3] = inpacket[0:3]
            response[4] = 0
            response[5] = 4
            response[6] = 1
            response[7] = 1
            response[8] = 1
            response[9] = relay

            print("Sending response:")
            showpacket(response)
            conn.send(response)
            continue

        if functioncode == 5:
            # write coil
            print("Function code 0x05 - write single coil")
            showpacket(inpacket[0:31])

            if packetlength != 6:
                print("{}: incorrect packet length for function code 0x06 - ignoring".format(progname), file=sys.stderr)
                showpacket(inpacket[0:31])
                continue

            addr = (inpacket[8] * 256) + inpacket[9]

            if (addr != 0):
                print("{}: this gateway only serves Modbus UDP packets with address of 0 - ignoring".format(progname), file=sys.stderr)
                continue

            stat = (inpacket[10] * 256) + inpacket[11]

            if ((stat != 0) and (stat != 0xFF00)):
                print("{}: this gateway only serves Modbus UDP packets with register count of 1 - ignoring".format(progname), file=sys.stderr)
                continue

            setrelaystatus(ipaddr, stat)

            response = bytearray(12)

            response[0:12] = inpacket[0:12]

            print("Sending response:")
            showpacket(response)
            conn.send(response)
            continue

        print("{}: unrecognised or unsupported packet".format(progname), file=sys.stderr)
        showpacket(inpacket[0:31])

########################################################################

#
# Main
#

progname = os.path.basename(sys.argv[0])

parser = argparse.ArgumentParser()
parser.add_argument("--ipaddr", help="IP address of the HS100/HS110 plug")
parser.add_argument("--port", help="port number to listen on", default=DEFAULT_MODBUS_PORT)
args = parser.parse_args()

ipaddr = args.ipaddr
port = int(args.port)

print("====== {} === HS100/110 IP address: {} === Modbus Port: {} ======".format(progname, ipaddr, port))

print("Creating TCP socket")
tcp = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)

print("Binding TCP socket")
tcp.bind(('', port))

print("Listening on TCP socket")
tcp.listen(10)

while True:
    print("Waiting to receive incoming Modbus connection over TCP")

    try:
        conn, clientaddress = tcp.accept()
    except ConnectionResetError:
        print("{}: got a ConnectionResetError - ignoring".format(progname), file=sys.stderr)
        continue

    print("Got connection from {}".format(clientaddress))

    handleconnection(conn)

    print("Connection closed")

########################################################################

# end of file
