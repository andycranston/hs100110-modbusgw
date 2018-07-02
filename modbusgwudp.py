#! /usr/bin/python3
#
# @(!--#) @(#) modbusgwudp.py, version 003, 02-july-2018
#
# modbus gateway over UDP for a TP-Link HS100/HS110 Smart WiFi Plug
#
# Links
#
#    https://www.softscheck.com/en/reverse-engineering-tp-link-hs110/
#    https://github.com/softScheck/tplink-smartplug
#    https://github.com/softScheck/tplink-smartplug/blob/master/tplink-smartplug.py
#    https://unserver.xyz/modbus-guide/
#

#
# imports
#

import sys
import os
import argparse
import socket

########################################################################

DEFAULT_MODBUS_PORT = "8502"

MAX_PACKET_LENGTH = 1024

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

udp = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

udp.bind(('', port))

while True:
    print("Waiting to receive incoming Modbus packet over UDP")

    try:
        databytes, clientaddress = udp.recvfrom(MAX_PACKET_LENGTH)
    except ConnectionResetError:
        print("{}: got a ConnectionResetError - ignoring".format(progname), file=sys.stderr)
        continue
        
    if len(databytes) < 6:
        print("{}: runt Modbus UDP packet received - ignoring".format(progname), file=sys.stderr)
        showpacket(databytes)
        continue

    packetlength = (databytes[4] * 256) + databytes[5]

    if (packetlength < 2):
        print("{}: Modbus UDP packet length too short to have any useful data in it - ignoring".format(progname), file=sys.stderr)
        showpacket(databytes)
        continue

    if (packetlength + 6) != len(databytes):
        print("{}: Modbus UDP packet has incorrect length - ignoring".format(progname), file=sys.stderr)
        showpacket(databytes)
        continue

    unitid = databytes[6]

    if unitid != 1:
        print("{}: this gateway only serves Modbus UDP packets with Unit ID of 1 - ignoring".format(progname), file=sys.stderr)
        showpacket(databytes)
        continue

    functioncode = databytes[7]

    if functioncode == 1:
        # read coil
        print("Function code 0x01 - read single coil")
        showpacket(databytes)

        if packetlength != 6:
            print("{}: incorrect packet length for function code 0x01 - ignoring".format(progname), file=sys.stderr)
            continue

        addr = (databytes[8] * 256) + databytes[9]

        if (addr != 0):
            print("{}: this gateway only serves Modbus UDP packets with address of 0 - ignoring".format(progname), file=sys.stderr)
            continue

        numr = (databytes[10] * 256) + databytes[11]

        if (numr != 1):
            print("{}: this gateway only serves Modbus UDP packets with register count of 1 - ignoring".format(progname), file=sys.stderr)
            continue

        relay = getrelaystatus(ipaddr)

        response = bytearray(6 + 4)

        response[0:3] = databytes[0:3]
        response[4] = 0
        response[5] = 4
        response[6] = 1
        response[7] = 1
        response[8] = 1
        response[9] = relay

        print("Sending response:")
        showpacket(response)
        udp.sendto(response, clientaddress)
        continue

    if functioncode == 5:
        # write coil
        print("Function code 0x05 - write single coil")
        showpacket(databytes)

        if packetlength != 6:
            print("{}: incorrect packet length for function code 0x06 - ignoring".format(progname), file=sys.stderr)
            showpacket(databytes)
            continue

        addr = (databytes[8] * 256) + databytes[9]

        if (addr != 0):
            print("{}: this gateway only serves Modbus UDP packets with address of 0 - ignoring".format(progname), file=sys.stderr)
            continue

        stat = (databytes[10] * 256) + databytes[11]

        if ((stat != 0) and (stat != 0xFF00)):
            print("{}: this gateway only serves Modbus UDP packets with register count of 1 - ignoring".format(progname), file=sys.stderr)
            continue

        setrelaystatus(ipaddr, stat)

        response = bytearray(len(databytes))

        response[0:12] = databytes[0:12]

        print("Sending response:")
        showpacket(response)
        udp.sendto(response, clientaddress)
        continue

    print("{}: unrecognised or unsupported packet".format(progname), file=sys.stderr)
    showpacket(databytes)

########################################################################

# end of file
