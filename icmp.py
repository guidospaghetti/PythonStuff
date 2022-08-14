#! /usr/bin/python3
import sys
import socket
import struct
import math
from pprint import pprint
import argparse
from random import randrange
import datetime
import netifaces


def internetChecksum(buf):
	# The checksum is the one's complement of the one's complement
	# sum of all fields, assuming the checksum is all zeros

	# Get data of packet into unsigned shorts
	formatString = '>'
	numShorts = math.ceil(len(buf) / 2)
	bufToChecksum = None
	if (numShorts * 2) - len(buf) == 1:
		newBuf = bytearray(numShorts*2)
		newBuf[:len(buf)] = buf
		bufToChecksum = newBuf
	else:
		bufToChecksum = buf

	formatString += ('H'*numShorts)
	fields = struct.unpack(formatString, bufToChecksum)

	# Sum all of them
	fieldSum = 0
	for field in fields:
		fieldSum += field

	# Calculate the carry amount
	carry = fieldSum >> 16

	# Add back the carry
	fieldSum = (fieldSum & 0xFFFF) + carry
	if fieldSum > 0xFFFF:
		# If adding carry cause another carry, repeat
		carry = fieldSum >> 16
		fieldSum = (fieldSum & 0xFFFF) + carry
	
	# Careful of return value, need to ensure not
	# returning any sign bits
	return (~fieldSum & 0xFFFF)
	

class IPv4Header:
	# Actual header fields
	version = 4
	headerLength = 5
	dscp = 0
	ecn = 0
	totalLength = None
	identification = None
	flags = 0
	fragmentOffset = 0
	ttl = 1
	protocol = None
	checksum = None
	srcIP = None
	destIP = None
	# Skipping options for now

	# Convience fields
	headerLenBytes = None
	srcIPStr = None
	destIPStr = None

	def readObject(self, buf):
		versionLength = struct.unpack('>B', buf[:1])[0]
		self.version = (versionLength & 0xF0) >> 4
		self.headerLength = (versionLength & 0x0F) >> 0
		self.headerLenBytes = self.headerLength * 4
		if self.headerLength > 5:
			# Ignoring for now TODO
			return -1

		header = struct.unpack('>BBHHHBBH4s4s', buf[:self.headerLenBytes])
		self.dscp = (header[1] & 0xFC) >> 2
		self.ecn = (header[1] & 0x03) >> 0
		self.totalLength = header[2]
		self.identification = header[3]
		self.flags = (header[4] & 0xE000) >> 13
		self.fragmentOffset = (header[4] & 0x1FFF) >> 0
		self.ttl = header[5]
		self.protocol = header[6]
		self.checksum = header[7]
		self.srcIP = header[8]
		self.destIP = header[9]
		
		self.srcIPStr = socket.inet_ntoa(self.srcIP)
		self.destIPStr = socket.inet_ntoa(self.destIP)

		return self.headerLenBytes
	
	def setDataLength(self, dataLength):
		self.totalLength = 20 + dataLength

	def calculateChecksum(self):

		tmpBuf = bytearray(20)

		self.checksum = 0
		size = self.writeObject(tmpBuf)
		if size < 0:
			return -1

		return internetChecksum(tmpBuf[:size])

	def writeObject(self, buf, index=0):
		if self.srcIP is None:
			if self.srcIPStr is not None:
				self.srcIP = socket.inet_aton(self.srcIPStr)
			else:
				print("No source IP set")
				return -1
		if self.destIP is None:
			if self.destIPStr is not None:
				self.destIP = socket.inet_aton(self.destIPStr)
			else:
				print("No destination IP set")
				return -1


		if self.totalLength is None or self.totalLength < 20:
			print("totalLength is invalid")
			return -1
		if self.protocol is None:
			return -1
		if self.identification is None:
			self.identification = randrange(0, 0xFFFF)

		if self.checksum is None:
			self.checksum = self.calculateChecksum()

		version_length = (self.version << 4) | (self.headerLength << 0)
		dcsp_ecn = (self.dscp << 2) | (self.ecn << 0)
		flags_fragOffset = (self.flags << 13) | (self.fragmentOffset << 0)

		# Trusting totalLength is right
		struct.pack_into('>BBHHHBBH4s4s', buf, index, version_length, dcsp_ecn,
			self.totalLength, self.identification, flags_fragOffset,
			self.ttl, self.protocol, self.checksum, self.srcIP,
			self.destIP)

		return 20


class ICMP_EchoRequest:
	data = None

	def readObject(self, buf):
		self.data = buf
		return len(buf)

	def writeObject(self, buf, index=0):
		if self.data is not None:
			buf[index:] = self.data
		return len(self.data)

class ICMP_EchoReply:
	data = None

	def readObject(self, buf):
		self.data = buf
		return len(buf)

	def writeObject(self, buf, index=0):
		if self.data is not None:
			buf[index:] = self.data
		return len(self.data)

class ICMP_Timestamp:
	identifier = None
	sequenceNum = None
	originateTimestamp = None

	def readObject(self, buf):
		message = struct.unpack('>HHI', buf)
		self.identifier = message[0]
		self.sequenceNum = message[1]
		self.originateTimestamp = message[2]
		return 8

	def writeObject(self, buf, index=0):
		if self.identifier is None:
			return -1
		if self.sequenceNum is None:
			return -1
		if self.originateTimestamp is None:
			return -1

		struct.pack_into('>HHI', buf, index, self.identifier,
			self.sequenceNum, self.originateTimestamp)

		return 8

class ICMP_TimestampReply:
	identifier = None
	sequenceNum = None
	originateTimestamp = None
	receiveTimestamp = None
	transmitTimestamp = None

	def readObject(self, buf):
		message = struct.unpack('>HHIII', buf)
		self.identifier = message[0]
		self.sequenceNum = message[1]
		self.originateTimestamp = message[2]
		self.receiveTimestamp = message[3]
		self.transmitTimestamp = message[4]
		return 16
	
	def writeObject(self, buf, index=0):
		struct.pack_into('>HHIII', buf, index, self.identifier,
			self.sequenceNum, self.originateTimestamp,
			self.receiveTimestamp, self.transmitTimestamp)

		return 16

class ICMPPacket:
	icmpType = None
	icmpCode = None
	icmpChecksum = None
	icmpData = None

	def readObject(self, buf):
		icmpHeader = struct.unpack('>BBH', buf[:4])
		self.icmpType = icmpHeader[0]
		self.icmpCode = icmpHeader[1]
		self.icmpChecksum = icmpHeader[2]

		offset = 4

		if self.icmpType == 0:
			self.icmpData = ICMP_EchoReply()
			offset += self.icmpData.readObject(buf[offset:])
		elif self.icmpType == 8:
			self.icmpData = ICMP_EchoRequest()
			offset += self.icmpData.readObject(buf[offset:])
		elif self.icmpType == 13:
			self.icmpData = ICMP_Timestamp()
			offset += self.icmpData.readObject(buf[offset:])
		elif self.icmpType == 14:
			self.icmpData = ICMP_TimestampReply()
			offset += self.icmpData.readObject(buf[offset:])
		else:
			print("Unsupported ICMP type: {},{}".format(self.icmpType, self.icmpCode))

		return offset

	def setType(self, icmpType):

		self.icmpType = icmpType

		if icmpType == 0:
			self.icmpCode = 0
			self.icmpData = ICMP_EchoReply()
		elif icmpType == 8:
			self.icmpCode = 0
			self.icmpData = ICMP_EchoRequest()
		elif icmpType == 13:
			self.icmpCode = 0
			self.icmpData = ICMP_Timestamp()
		elif icmpType == 14:
			self.icmpCode = 0
			self.icmpData = ICMP_TimestampReply()
		else:
			self.icmpType = None
			print("Unsupported ICMP type: {},{}".format(self.icmpType, self.icmpCode))

	# TODO add calculateChecksum method
	def calculateChecksum(self):

		tmpBuf = bytearray(1500)
		self.icmpChecksum = 0
		size = self.writeObject(tmpBuf)
		if size < 0:
			return size

		return internetChecksum(tmpBuf[:size])

	def writeObject(self, buf, index=0):
		if self.icmpType is None:
			print('icmpType is not set')
			return -1
		if self.icmpCode is None:
			print('icmpCode is not set')
			return -1
		if self.icmpData is None:
			print('icmpData is not set')
			return -1
		
		if self.icmpChecksum is None:
			self.icmpChecksum = self.calculateChecksum()
			if self.icmpChecksum < 0:
				return -1
		offset = 0

		struct.icmpType = 11
		struct.pack_into('>BBH', buf, index, self.icmpType, self.icmpCode, self.icmpChecksum)
		offset += 4

		offset += self.icmpData.writeObject(buf, index+offset)

		return offset

class IPPacket:
	header = IPv4Header()
	data = None

	def readObject(self, buf):
		bytesRead = self.header.readObject(buf)
		if self.header.protocol == socket.IPPROTO_ICMP:
			self.data = ICMPPacket()
			bytesRead += self.data.readObject(buf[bytesRead:])

		return bytesRead
	
	def writeObject(self, buf, index=0):
		numWritten = 0
		if self.data is not None:
			numWritten += self.data.writeObject(buf, 20)
			if numWritten < 0:
				print('Failed to write packet data out')
				return numWritten
		self.header.setDataLength(numWritten)
		numWritten += self.header.writeObject(buf)

		return numWritten


parser = argparse.ArgumentParser(description='Send and receive different types of ICMP packets')
group = parser.add_mutually_exclusive_group()
group.add_argument('-p', '--ping', metavar='IP', help='Send an ICMP Echo Request (ping) to the given IP')
group.add_argument('-t', '--timestamp', metavar='IP', help='Send an ICMP Timestamp request to the given IP')
group.add_argument('-l', '--listen', action='store_true', help='Just listen for all ICMP packets')

args = parser.parse_args()

sourceIP = ""

ifaces = netifaces.interfaces()
for interface in ifaces:
	ifaceInfo = netifaces.ifaddresses(interface)
	if netifaces.AF_INET in ifaceInfo:
		address = ifaceInfo[netifaces.AF_INET][0]["addr"]
		if address != "127.0.0.1":
			sourceIP = address
			break

if sourceIP == "":
	print("Failed to find appropriate network interface")
	sys.exit(1)

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
s.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

if args.listen:
	print("Will listen for ICMP")
	while 1:
		data, addr = s.recvfrom(1500)
		print("Packet from {}".format(addr))
		if len(data) > 0:
			packet = IPPacket()
			packet.readObject(data)
			pprint(vars(packet.header))
			pprint(vars(packet.data))

elif args.ping:
	print("Sending ping to {}".format(args.ping))

	packet = IPPacket()
	packet.data = ICMPPacket()
	packet.data.setType(8)
	packet.data.icmpData.data = b'123456789'

	packet.header.protocol = socket.IPPROTO_ICMP
	packet.header.srcIPStr = sourceIP
	packet.header.destIPStr = args.ping
	packet.header.ttl = 30

	buf = bytearray(1500)
	size = packet.writeObject(buf)

	s.sendto(buf[:size], (packet.header.destIPStr, 1))

	print("Will listen for ICMP")

	while 1:
		data, addr = s.recvfrom(1500)
		print("Packet from {}".format(addr))
		if len(data) > 0:
			packet = IPPacket()
			packet.readObject(data)
			pprint(vars(packet.header))
			pprint(vars(packet.data))
			if packet.header.srcIPStr == sourceIP:
				continue
			else:
				break

elif args.timestamp:
	print("Requesting timestamp from {}".format(args.timestamp))

	packet = IPPacket()
	packet.data = ICMPPacket()
	packet.data.setType(13)
	packet.data.icmpData.identifier = 1000
	packet.data.icmpData.sequenceNum = 10
	now = datetime.datetime.utcnow()
	midnight = now.replace(hour=0,minute=0,second=0,microsecond=0)
	since = now - midnight
	msecSince = int(since / datetime.timedelta(milliseconds=1))
	packet.data.icmpData.originateTimestamp = msecSince

	packet.header.protocol = socket.IPPROTO_ICMP
	packet.header.srcIPStr = sourceIP
	packet.header.destIPStr = args.timestamp
	packet.header.ttl = 30

	buf = bytearray(1500)
	size = packet.writeObject(buf)

	s.sendto(buf[:size], (packet.header.destIPStr, 1))

	print("Will listen for ICMP")

	while 1:
		data, addr = s.recvfrom(1500)
		print("Packet from {}".format(addr))
		if len(data) > 0:
			packet = IPPacket()
			packet.readObject(data)
			pprint(vars(packet.header))
			pprint(vars(packet.data))
			pprint(vars(packet.data.icmpData))
			if packet.header.srcIPStr == sourceIP:
				continue
			else:
				break
else:
	parser.print_help()
	sys.exit(1)
