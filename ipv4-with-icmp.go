package go_packets_crafting

import (
	"encoding/binary"
	"fmt"
	"github.com/buldumac/go-packets-crafting/rfc1071"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// Low-level packets are fun
//
// Below is a complete, self-contained Linux example in Go that crafts a full IPv4 packet (IP header + ICMP payload),
// computes the IP and ICMP checksums, and sends it using a raw socket.

// Important notes before the code:
//
// 1. We must run this as root (or have CAP_NET_RAW) on Linux
// 2. On some OSes (macOS/BSD) raw-socket behavior differs
// 3. If we only want to craft the transport payload (ICMP/UDP/TCP) and let the kernel build the IP header,
//    we can use net.Dial("ip4:icmp", ...) or golang.org/x/net/ipv4 helpers instead.

func buildIPv4Header(src, dst net.IP, payloadLen int, protocol uint8, identification uint16, timeToLive uint8) []byte {
	/*
		 0                   1                   2                   3
		 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		+---------------------------------------------------------------+
		|Version|  IHL  |   Type of Service  |        Total Length      |
		+---------------------------------------------------------------+
		|        Identification         |Flags|   Fragment Offset      |
		+---------------------------------------------------------------+
		|  Time to Live |   Protocol    |       Header Checksum      |
		+---------------------------------------------------------------+
		|                     Source Address (32 bits)                  |
		+---------------------------------------------------------------+
		|                  Destination Address (32 bits)                |
		+---------------------------------------------------------------+
		|                    (Options - if IHL > 5)                     |
		+---------------------------------------------------------------+
	*/
	ipHeader := make([]byte, 20) // no options
	ipHeader[0] = (4 << 4) | 5   // Version=4, IHL=5 (20 bytes)
	ipHeader[1] = 0              // TOS
	totalLen := 20 + payloadLen
	binary.BigEndian.PutUint16(ipHeader[2:], uint16(totalLen))
	binary.BigEndian.PutUint16(ipHeader[4:], identification)
	binary.BigEndian.PutUint16(ipHeader[6:], 0) // flags +  frag offset
	ipHeader[8] = timeToLive
	ipHeader[9] = protocol

	// checksum will be set later
	// when it's computed, we must treat the checksum field itself as zero
	//
	// we should build the header bytes exactly as they will appear on the wire except
	// set the checksum field(bytes 10-11) to 0x000
	//
	// zero value for byte is 0 but we can set it explicitly
	ipHeader[10] = 0x0
	ipHeader[11] = 0x0

	copy(ipHeader[12:16], src.To4())
	copy(ipHeader[16:20], dst.To4())

	headerCheckSum := rfc1071.Checksum(ipHeader)
	binary.BigEndian.PutUint16(ipHeader[10:], headerCheckSum)

	return ipHeader
}

func buildICMPEcho(id, seq uint16, payload []byte) []byte {
	/*
		 0                   1                   2                   3
		 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		+---------------------------------------------------------------+
		|     Type (8 bits)     |     Code (8 bits)      |  Checksum    |
		+---------------------------------------------------------------+
		|         Identifier (16 bits)         |    Sequence (16 bits)|
		+---------------------------------------------------------------+
		|                         Payload (variable)                    |
		|                     (optional padding for checksum)           |
		+---------------------------------------------------------------+
	*/
	icmp := make([]byte, 8+len(payload))
	icmp[0] = 8 // Type = 8 (Echo)
	icmp[1] = 0 // Code = 0
	// checksum set later
	binary.BigEndian.PutUint16(icmp[4:], id)
	binary.BigEndian.PutUint16(icmp[6:], seq)
	copy(icmp[8:], payload)

	// using same checksum logic (RFC 1071)
	cs := rfc1071.Checksum(icmp)
	binary.BigEndian.PutUint16(icmp[2:], cs)
	return icmp

}

func main() {
	// if len(os.Args) < 3 {
	// 	fmt.Fprintf(os.Stderr, "Usage: %s <src-ip> <dst-ip>\n", os.Args[0])
	// 	os.Exit(1)
	// }
	//
	// srcIpStr := os.Args[1]
	// dstIpStr := os.Args[2]

	srcIpStr := "192.168.0.99"
	dstIpStr := "192.168.0.1"

	srcIP := net.ParseIP(srcIpStr).To4()
	dstIP := net.ParseIP(dstIpStr).To4()
	if srcIP == nil || dstIP == nil {
		_, _ = fmt.Fprintln(os.Stderr, "Invalid IPv4 address")
		os.Exit(1)
	}

	// Display all interfaces with assigned IP(s)
	ifaces, err := net.Interfaces()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "failed to get interfaces")
		os.Exit(1)
	}
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			fmt.Printf("%s: %s\n", i.Name, addr.String())
		}
	}

	// Build ICMP payload (Echo request)
	icmpPayload := []byte("hello-from-booldomac")
	icmp := buildICMPEcho(0x1234, 1, icmpPayload)

	// Build IPv4 header carrying ICMP (protocol 1)
	ip := buildIPv4Header(srcIP, dstIP, len(icmp), 1, 0xabcd, 64)

	packet := append(ip, icmp...) // full IP packet, header included

	// Create raw socket
	// Use IPPROTO_RAW so kernel won't touch IP header when IP_HDRINCL=1
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		fmt.Fprintf(os.Stderr, "socket: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		errClose := unix.Close(fd)
		if errClose != nil {
			fmt.Fprintf(os.Stderr, "failed to close socket")
		}
	}()

	// Tell kernel we provide the IP header
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		fmt.Fprintf(os.Stderr, "setsockopt IP_HDRINCL: %v\n", err)
		os.Exit(1)
	}

	// Build sockaddr
	var sa unix.SockaddrInet4
	copy(sa.Addr[:], dstIP)

	// Send packet (may require root)
	if err := unix.Sendto(fd, packet, 0, &sa); err != nil {
		fmt.Fprintf(os.Stderr, "sendto: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Packet sent. Waiting for possible reply (read from raw socket)...")
	// optional: receive responses (ICMP reply) - open a separate socket for reading ICMP replies
	recvFd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
	if err != nil {
		fmt.Fprintf(os.Stderr, "recv socket: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		errClose := unix.Close(recvFd)
		if errClose != nil {
			fmt.Fprintf(os.Stderr, "failed to close socket")
		}
	}()

	_ = unix.SetNonblock(recvFd, true)

	// naive loop to poll for a short time
	buf := make([]byte, 1500)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		n, from, err := unix.Recvfrom(recvFd, buf, 0)
		if err != nil {
			// non-blocking might return EAGAIN; ignore and continue
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if n > 0 {
			fmt.Printf("Got %d bytes from %v\n", n, from)
			// print a short hex preview
			fmt.Printf("%x\n", buf[:n])
			break
		}
	}
}

// [[ Explanations - what to change / why each part matters ]]
//
// - unix.Socket(AF_INET, SOCK_RAW, IPPROTO_RAW) opens a raw IP socket. On Linux, IPPROTO_RAW allows
//   sending custom IP headers; IP_HDRINCL tells the kernel not to overwrite the header.
//
// - buildIPv4Header constructs a 20-byte IPv4 header: version/IHL, total length, id, flags/frag offset,
//   TTL, protocol, checksum, src/dst. We must compute and set the header checksum ourselves.
//
// - ICMP also needs its own checksum; the checksum function is a standard RFC 1071 implementation
//   (add 16-bit words, add carries, invert)
//
// - SendTo(fd, packet, ..., SockaddrInet4{Addr: dst}) sends the whole packet to the target IP
//
// - If we want to craft TCP or UDP packets as well, we must also craft the TCP/UDP header and compute
//   their checksums (TCP/UDP use pseudo-headers that include IP src/dst/protocol/length). For UDP,
//   kernel may accept raw UDP datagrams easier via AF_INET + SOCK_DGRAM with control options, but
//   crafting full IP+UDP still requires to build pseudo-header checksum.
//
// - On modern systems we can often use golang.org/x/net/ipv4 to help marshal headers and control some
//   socket options - but unix or syscall lets us build every byte ourself
//

// [[ Tips and Gotchas ]]
// - Root/CAP_NET_RAW is required
//
// - Some kernels may drop outgoing packets with mismatched checksums (especially for TCP), or firewall
//   rules(iptables) may block raw packets
//
// - On Linux, using protocol IPPROTO_RAW vs IPPROTO_ICMP in socket creation changes kernel behavior;
//   For sending a packet with a complete IP header use IPPROTO_RAW and set IP_HDRINCL
//
// - When crafting TCP you must compute the TCP checksum using a pseudo-header (src/dst/proto+length)
//
// - For testing, use a local VM or a controlled lab. Sending spoofed source IPs on the public internet can
//   make troubles
