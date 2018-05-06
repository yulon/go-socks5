package socks5

import (
	"errors"
	"fmt"
	"net"
	"sync"
)

const maxUDPPacketSize = 2 * 1024

var udpClientSrcAddr = &net.UDPAddr{IP: net.IPv4zero, Port: 0}

var udpPacketBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, maxUDPPacketSize, maxUDPPacketSize)
	},
}

func getUDPPacketBuffer() []byte {
	return udpPacketBufferPool.Get().([]byte)
}

func putUDPPacketBuffer(p []byte) {
	p = p[:cap(p)]
	udpPacketBufferPool.Put(p)
}

//FIXME: insecure implementation of UDP server, anyone could send package here without authentication

func (s *Server) handleUDP(udpConn *net.UDPConn) {
	for {
		buffer := getUDPPacketBuffer()
		n, src, err := udpConn.ReadFromUDP(buffer)
		if err != nil {
			s.config.Logger.Printf("[ERR] udp socks: Failed to accept udp traffic: %v", err)
		}
		buffer = buffer[:n]
		go func() {
			defer putUDPPacketBuffer(buffer)
			s.serveUDPConn(buffer, func(data []byte) error {
				_, err := udpConn.WriteToUDP(data, src)
				return err
			})
		}()
	}
}

/*********************************************************
    UDP PACKAGE to proxy
    +----+------+------+----------+----------+----------+
    |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
    +----+------+------+----------+----------+----------+
    | 2  |  1   |  1   | Variable |    2     | Variable |
    +----+------+------+----------+----------+----------+
**********************************************************/

// ErrUDPFragmentNoSupported UDP fragments not supported error
var ErrUDPFragmentNoSupported = errors.New("")

func (s *Server) serveUDPConn(udpPacket []byte, reply func([]byte) error) error {
	// RSV  Reserved X'0000'
	// FRAG Current fragment number, donnot support fragment here
	header := []byte{0, 0, 0}
	if len(udpPacket) <= 3 {
		err := fmt.Errorf("short UDP package header, %d bytes only", len(udpPacket))
		s.config.Logger.Printf("[ERR] udp socks: Failed to get UDP package header: %v", err)
		return err
	}
	if header[0] != 0x00 || header[1] != 0x00 {
		err := fmt.Errorf("unsupported socks UDP package header, %+v", header[:2])
		s.config.Logger.Printf("[ERR] udp socks: Failed to parse UDP package header: %v", err)
		return err
	}
	if header[2] != 0x00 {
		s.config.Logger.Printf("[ERR] udp socks: %+v", ErrUDPFragmentNoSupported)
		return ErrUDPFragmentNoSupported
	}

	// Read in the destination address
	targetAddrRaw := udpPacket[3:]
	targetAddrSpec := &AddrSpec{}
	targetAddrRawSize := 0
	errShortAddrRaw := func() error {
		err := fmt.Errorf("short UDP package Addr. header, %d bytes only", len(targetAddrRaw))
		s.config.Logger.Printf("[ERR] udp socks: Failed to get UDP package header: %v", err)
		return err
	}
	if len(targetAddrRaw) < 1+4+2 /* ATYP + DST.ADDR.IPV4 + DST.PORT */ {
		return errShortAddrRaw()
	}
	targetAddrRawSize = 1
	switch targetAddrRaw[0] {
	case AddressIPv4:
		targetAddrSpec.IP = net.IP(targetAddrRaw[targetAddrRawSize : targetAddrRawSize+4])
		targetAddrRawSize += 4
	case AddressIPv6:
		if len(targetAddrRaw) < 1+16+2 {
			return errShortAddrRaw()
		}
		targetAddrSpec.IP = net.IP(targetAddrRaw[1 : 1+16])
		targetAddrRawSize += 16
	case AddressDomainName:
		addrLen := int(targetAddrRaw[1])
		if len(targetAddrRaw) < 1+1+addrLen+2 {
			return errShortAddrRaw()
		}
		targetAddrSpec.FQDN = string(targetAddrRaw[1+1 : 1+1+addrLen])
		targetAddrRawSize += (1 + addrLen)
	default:
		s.config.Logger.Printf("[ERR] udp socks: Failed to get UDP package header: %v", errUnrecognizedAddrType)
		return errUnrecognizedAddrType
	}
	targetAddrSpec.Port = (int(targetAddrRaw[targetAddrRawSize]) << 8) | int(targetAddrRaw[targetAddrRawSize+1])
	targetAddrRawSize += 2
	targetAddrRaw = targetAddrRaw[:targetAddrRawSize]

	// resolve addr.
	if targetAddrSpec.FQDN != "" {
		_, addr, err := s.config.Resolver.Resolve(nil, targetAddrSpec.FQDN)
		if err != nil {
			err := fmt.Errorf("Failed to resolve destination '%v': %v", targetAddrSpec.FQDN, err)
			s.config.Logger.Printf("[ERR] udp socks: %+v", err)
			return err
		}
		targetAddrSpec.IP = addr
	}

	// make a writer and write to dst
	targetUDPAddr, err := net.ResolveUDPAddr("udp", targetAddrSpec.Address())
	if err != nil {
		err := fmt.Errorf("Failed to resolve destination UDP Addr '%v': %v", targetAddrSpec.Address(), err)
		return err
	}
	target, err := net.DialUDP("udp", udpClientSrcAddr, targetUDPAddr)
	if err != nil {
		err = fmt.Errorf("Connect to %v failed: %v", targetUDPAddr, err)
		s.config.Logger.Printf("[ERR] udp socks: %+v", err)
		return err
	}
	defer target.Close()

	// write data to target and read the response back
	if _, err := target.Write(udpPacket[len(header)+len(targetAddrRaw):]); err != nil {
		s.config.Logger.Printf("[ERR] udp socks: fail to write udp data to dest %s: %+v",
			targetUDPAddr.String(), err)
		return err
	}
	respBuffer := getUDPPacketBuffer()
	defer putUDPPacketBuffer(respBuffer)
	copy(respBuffer[0:len(header)], header)
	copy(respBuffer[len(header):len(header)+len(targetAddrRaw)], targetAddrRaw)
	n, err := target.Read(respBuffer[len(header)+len(targetAddrRaw):])
	if err != nil {
		s.config.Logger.Printf("[ERR] udp socks: fail to read udp resp from dest %s: %+v",
			targetUDPAddr.String(), err)
		return err
	}
	respBuffer = respBuffer[:len(header)+len(targetAddrRaw)+n]

	if reply(respBuffer); err != nil {
		s.config.Logger.Printf("[ERR] udp socks: fail to send udp resp back: %+v", err)
		return err
	}
	return nil
}
