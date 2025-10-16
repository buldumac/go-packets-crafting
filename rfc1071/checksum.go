package rfc1071

import "encoding/binary"

// Checksum calculates the 16-bit one's complement checksum (RFC 1071)
func Checksum(data []byte) uint16 {
	var sum uint32
	n := len(data)
	for i := 0; i+1 < n; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}

	// if number of bytes are odd
	if n%2 == 1 {
		lastByte := data[n-1]
		// << 8 -> shift left 8 bits or 1 byte
		// example: 0x3 << 8 -> 0x0300 or 0x300 , they are the same but it's easier to interpret 0x0300 sa 2 bytes, 0x03 and 0x00
		sum += uint32(lastByte) << 8
	}

	// add carries
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return ^uint16(sum)
}
