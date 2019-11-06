package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"
)

func (s *Server) handleUDP(svrUDPConn *net.UDPConn) {
	p := make([]byte, 4096)
	for {
		n, cltUDPAddr, err := svrUDPConn.ReadFromUDP(p)
		if err != nil {
			s.config.Logger.Printf("udp socks: Failed to accept udp traffic: %v", err)
			return
		}
		destAddr, data, err := parseUDPReq(p[:n])
		if err != nil {
			return
		}
		udpPxyConn, err := s.proxyUDP(cltUDPAddr, destAddr, svrUDPConn)
		if err != nil {
			return
		}
		rUDPAddr, err := net.ResolveUDPAddr("udp", destAddr)
		if err != nil {
			return
		}
		udpPxyConn.WriteTo(data, rUDPAddr)
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

type udpProxyHeader struct {
	RSV  uint16 // Reserved X'0000'
	FRAG byte   // Current fragment number, donnot support fragment here
}

var ErrUDPFragmentNoSupported = errors.New("UDP fragments not supported")

func parseUDPReq(pkt []byte) (string, []byte, error) {
	if len(pkt) <= 3 {
		return "", nil, fmt.Errorf("short UDP package header, %d bytes only", len(pkt))
	}
	r := bytes.NewReader(pkt)
	var h udpProxyHeader
	binary.Read(r, binary.BigEndian, &h)
	if h.RSV != 0 {
		return "", nil, fmt.Errorf("unsupported socks UDP package header, %+v", h.RSV)
	}
	if h.FRAG != 0 {
		return "", nil, ErrUDPFragmentNoSupported
	}
	addrSpec, err := readAddrSpec(r)
	if err != nil {
		return "", nil, err
	}
	return addrSpec.Address(), pkt[int(r.Size())-r.Len():], nil
}

func makeUDPResp(addr *AddrSpec, data []byte) []byte {
	buf := bytes.NewBuffer([]byte{0, 0, 0})
	addr.WriteTo(buf)
	buf.Write(data)
	return buf.Bytes()
}

type udpPxyConnInfo struct {
	conn   net.PacketConn
	lastTS int64
}

func (s *Server) proxyUDP(cltUDPAddr *net.UDPAddr, destAddr string, svrUDPConn *net.UDPConn) (net.PacketConn, error) {
	cltAddrStr := cltUDPAddr.String()

	v, exist := s.udpPxyConns.Load(cltAddrStr)
	if exist && v != nil {
		upci := v.(*udpPxyConnInfo)
		atomic.StoreInt64(&upci.lastTS, time.Now().Unix())
		return upci.conn, nil
	}

	for atomic.LoadInt32(&s.udpPxyConnC) > 4096 {
		var key interface{}
		var upci *udpPxyConnInfo
		s.udpPxyConns.Range(func(k interface{}, v interface{}) bool {
			soupci := v.(*udpPxyConnInfo)
			if upci == nil || atomic.LoadInt64(&soupci.lastTS) < atomic.LoadInt64(&upci.lastTS) {
				key = k
				upci = soupci
			}
			return true
		})
		atomic.AddInt32(&s.udpPxyConnC, -1)
		s.udpPxyConns.Delete(key)
		upci.conn.Close()
	}

	lnPkt := s.config.ListenPacket
	if lnPkt == nil {
		lnPkt = func(ctx context.Context, network string) (net.PacketConn, error) {
			return net.ListenPacket(network, "0.0.0.0:0")
		}
	}
	var err error
	udpPxyConn, err := lnPkt(context.Background(), "udp")
	if err != nil {
		return nil, err
	}

	upci := &udpPxyConnInfo{udpPxyConn, time.Now().Unix()}
	v, loaded := s.udpPxyConns.LoadOrStore(cltAddrStr, upci)
	if loaded {
		udpPxyConn.Close()
		upci = v.(*udpPxyConnInfo)
		atomic.StoreInt64(&upci.lastTS, time.Now().Unix())
		return upci.conn, nil
	}
	atomic.AddInt32(&s.udpPxyConnC, 1)

	go func() {
		p := make([]byte, 2048)
		defer udpPxyConn.Close()
		for {
			n, destAddr, err := udpPxyConn.ReadFrom(p)
			if err != nil {
				s.config.Logger.Printf("udp socks: fail to read udp resp from dest %v: %+v",
					destAddr, err)
				return
			}
			atomic.StoreInt64(&upci.lastTS, time.Now().Unix())
			rUDPAddr, ok := destAddr.(*net.UDPAddr)
			if !ok {
				destAddrStr := destAddr.String()
				rUDPAddr, err = net.ResolveUDPAddr("udp", destAddrStr)
				if err != nil {
					continue
				}
			}
			_, err = svrUDPConn.WriteToUDP(makeUDPResp(&AddrSpec{IP: rUDPAddr.IP, Port: rUDPAddr.Port}, p[:n]), cltUDPAddr)
			if err != nil {
				return
			}
		}
	}()
	return udpPxyConn, nil
}
