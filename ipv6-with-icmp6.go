package main

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"net"
	"os"
	"time"
)

const (
	NextHeaderRouting  = 43
	NextHeaderFragment = 44
	NextHeaderICMPv6   = 58
	IPv6HeaderLen      = 40
)

/*
                 ASCII diagram of an IPv6 header
                  40-byte fixed header structure
                      40-byte == 320bits

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version| Traffic Class |           Flow Label                  |
| 4bits |     8bits     |               20bits                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Payload Length         |  Next Header  |   Hop Limit  |
|             16bits             |      8bits    |     8bits    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                         Source Address                        |
|                         (128 bits)                           |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                      Destination Address                      |
|                         (128 bits)                           |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 - Version (4 bits): IPv6 version number, always 6
 - Traffic Class (8 bits): like DSCP, for QoS
 - Flow Label (20 bits): for special flow handling
 - Payload Length (16 bits): length of payload after the IPv6 (not including header itself)
 - Next Header (8 bits): type of header following IPv6 header (TCP, UDP, ICMPv6, etc.)
 - Hop Limit (8 bits): same as TTL in IPv4
 - Source Address (128 bits): IPv6 address of sender
 - Destination Address (128 bits): IPv6 address of recipient

There are also extension headers. Extension headers are optional headers inserted after the IPv6 base header.

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| IPv6 Base Header (Next Header -> Hop-by-Hop Options)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Hop-by-Hop Options Header (Next Header -> Routing Header)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Routing Header (Next Header -> TCP)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| TCP Header                                                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

func buildIPv6Header(
	srcIP net.IP,
	dstIP net.IP,
	trafficClass uint8, // 8 bits or 1 byte
	flowLabel uint32,   // only 20 bites are used from 32
	payloadLen uint16,
	nextHeader uint8,
	hopLimit uint8,
) ([]byte, error) {
	if len(srcIP) != net.IPv6len || len(dstIP) != net.IPv6len {
		return nil, fmt.Errorf("source and destination IPs must be 16 bytes IPv6 addresses")
	}

	header := make([]byte, IPv6HeaderLen)

	// Version (4 bits)
	// Traffic Class (8 bits)
	// Flow label (20 bits)
	// Pack into first 4 bytes or 32 bits
	// |4b ver|8b TC|20b FL|
	// version = 6
	version := uint32(6)
	tc := uint32(trafficClass)
	fl := flowLabel & 0x000FFFFF // mask to 20 bits

	// Compose first 4 bytes:
	// bits 0-3: version (4b)
	// bits 4-11: traffic class (8b)
	// bits 12-31: flow label (20b)
	version_trafficClass_flowLabel := (version << 28) | (tc << 20) | fl
	binary.BigEndian.PutUint32(header[0:4], version_trafficClass_flowLabel)

	// Payload Length (16 bits)
	binary.BigEndian.PutUint16(header[4:6], payloadLen)

	// Next Header (8 bits)
	// it's just 1 byte, no endianess is needed here
	header[6] = nextHeader

	// Hop Limit (8 bits)
	// it's just 1 byte, no endianess is needed here
	header[7] = hopLimit

	// Source Address (128 bits)
	copy(header[8:24], srcIP.To16())

	// Destination Address (128 bits)
	copy(header[24:40], dstIP.To16())

	return header, nil
}

func buildICMPv6EchoRequest(identifier, sequence uint16, payload []byte, srcIP, dstIP net.IP) ([]byte, error) {
	/*
	  0                   1                   2                   3
	  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 |     Type      |     Code      |          Checksum             |
	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 |           Identifier          |        Sequence Number         |
	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 |                                                               |
	 |                       ICMPv6 Payload                          |
	 |                                                               |
	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	 - Type (8 bits): for Echo Request should be 128
	 - Code (8 bits): usually 0 for Echo Request
	 - Checksum (16 bits): checksum over ICMPv6 message + IPv6 pseudo-header
	 - Identifier (16 bits): used to match requests/replies (can be arbitrary)
	 - Sequence Number (16 bits): increment per request
	 - Payload: optional data (like timestamp or arbitrary bytes)
	*/

	// ICMPv6 header is 8 bytes + payload
	packetLen := 8 + len(payload)
	packet := make([]byte, packetLen)

	// Type (128 = Echo Request)
	packet[0] = 128

	// Code = 0
	packet[1] = 0

	// Checksum set to 0 initially, will calculate later
	packet[2] = 0
	packet[3] = 0

	// Identifier
	binary.BigEndian.PutUint16(packet[4:6], identifier)

	// Sequence Number
	binary.BigEndian.PutUint16(packet[6:8], sequence)

	// Payload
	copy(packet[8:], payload)

	// Calculate checksum (including IPv6 pseudo-header)
	calculatedChecksum := icmpv6Checksum(packet, srcIP, dstIP)
	binary.BigEndian.PutUint16(packet[2:4], calculatedChecksum)

	return packet, nil

}

// icmpv6Checksum calculates the ICMPv6 checksum including the IPv6 pseudo-header
func icmpv6Checksum(data []byte, srcIP, dstIP net.IP) uint16 {
	// IPv6 pseudo-header length
	length := uint32(len(data))

	// Build pseudo-header
	psHeader := make([]byte, 40)
	copy(psHeader[0:16], srcIP.To16())
	copy(psHeader[16:32], dstIP.To16())
	binary.BigEndian.PutUint32(psHeader[32:36], length)
	psHeader[39] = 58 // Next header = 58 for ICMPv6

	// Calculate checksum over pseudo-header + data
	sum := checksum(psHeader)
	sum += checksum(data)

	// Fold to 16 bits
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return ^uint16(sum)
}

// checksum calculates the Internet checksum for the given data
func checksum(data []byte) uint32 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	return sum
}

func main() {
	filePcap, err := os.Create("icmpv6.pcap")
	if err != nil {
		panic(err)
	}
	defer func() {
		_ = filePcap.Close()
	}()

	w := pcapgo.NewWriter(filePcap)
	err = w.WriteFileHeader(1<<16-1, layers.LinkTypeEthernet)
	if err != nil {
		panic(err)
	}

	srcIPv6 := net.ParseIP("2001:db8::5")
	dstIPv6 := net.ParseIP("2001:db8::6")
	trafficClass := uint8(0)
	flowLabel := uint32(0)
	nextHeader := uint8(58) // ICMPv6
	hopLimitTTL := uint8(64)

	payloadICMPv6 := []byte("HELLO WORLD ICMP V6")
	icmpV6Packet, err := buildICMPv6EchoRequest(0x789, 2000, payloadICMPv6, srcIPv6, dstIPv6)
	if err != nil {
		panic(err)
	}

	payloadLength := uint16(len(icmpV6Packet))

	ipv6Header, err := buildIPv6Header(srcIPv6, dstIPv6, trafficClass, flowLabel, payloadLength, nextHeader, hopLimitTTL)
	if err != nil {
		panic(err)
	}

	ethernet := &layers.Ethernet{
		SrcMAC:       []byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5},
		DstMAC:       []byte{0x6, 0x7, 0x8, 0x9, 0xa, 0xf},
		EthernetType: layers.EthernetTypeIPv6,
	}

	layersBuffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(layersBuffer, gopacket.SerializeOptions{}, ethernet, gopacket.Payload(ipv6Header),
		gopacket.Payload(icmpV6Packet))
	if err != nil {
		panic(err)
	}

	bufferBytes := layersBuffer.Bytes()
	lenBufferBytes := len(bufferBytes)

	err = w.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		Length:        lenBufferBytes,
		CaptureLength: lenBufferBytes,
	}, bufferBytes)
	if err != nil {
		panic(err)
	}

	fmt.Printf("ICMPv6 (bytes: %d):\n%x\n", lenBufferBytes, bufferBytes)

}
