package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

/******************************************************
    Requests of client:

    +----+-----+-------+------+----------+----------+
    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  | X'00' |  1   | Variable |    2     |
    +----+-----+-------+------+----------+----------+
*******************************************************/

// CMD declaration
const (
	// CommandConnect CMD CONNECT X'01'
	CommandConnect = uint8(1)
	// CommandBind CMD BIND X'02'. The BIND request is used in protocols
	// which require the client to accept connections from the server.
	CommandBind = uint8(2)
	// CommandAssociate CMD UDP ASSOCIATE X'03'.  The UDP ASSOCIATE request
	// is used to establish an association within the UDP relay process to
	// handle UDP datagrams.
	CommandAssociate = uint8(3)
)

// ATYP address type of following address declaration
const (
	// AddressIPv4 IP V4 address: X'01'
	AddressIPv4 = uint8(1)
	// AddressDomainName DOMAINNAME: X'03'
	AddressDomainName = uint8(3)
	// AddressIPv6 IP V6 address: X'04'
	AddressIPv6 = uint8(4)
)

/******************************************************
    Response of server:

    +----+-----+-------+------+----------+----------+
    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  | X'00' |  1   | Variable |    2     |
    +----+-----+-------+------+----------+----------+
*******************************************************/

// REP field declaration
const (
	// ReplySucceeded X'00' succeeded
	ReplySucceeded uint8 = iota
	// ReplyServerFailure X'01' general SOCKS server failure
	ReplyServerFailure
	// ReplyRuleFailure X'02' connection not allowed by ruleset
	ReplyRuleFailure
	// ReplyNetworkUnreachable X'03' Network unreachable
	ReplyNetworkUnreachable
	// ReplyHostUnreachable X'04' Host unreachable
	ReplyHostUnreachable
	// ReplyConnectionRefused X'05' Connection refused
	ReplyConnectionRefused
	// ReplyTTLExpired X'06' TTL expired
	ReplyTTLExpired
	// ReplyCommandNotSupported X'07' Command not supported
	ReplyCommandNotSupported
	// ReplyAddrTypeNotSupported X'08' Address type not supported
	ReplyAddrTypeNotSupported
)

var errUnrecognizedAddrType = fmt.Errorf("unrecognized address type")

// zeroBindAddr used for TCP connect,  BND.ADDR and BND.PORT is unused
var zeroBindAddr = AddrSpec{IP: net.IPv4zero, Port: 1080}

// AddressRewriter is used to rewrite a destination transparently
type AddressRewriter interface {
	Rewrite(ctx context.Context, request *Request) (context.Context, *AddrSpec)
}

// AddrSpec is used to return the target AddrSpec
// which may be specified as IPv4, IPv6, or a FQDN
type AddrSpec struct {
	FQDN string
	IP   net.IP
	Port int
}

func (a *AddrSpec) String() string {
	if a.FQDN != "" {
		return fmt.Sprintf("%s (%s):%d", a.FQDN, a.IP, a.Port)
	}
	return fmt.Sprintf("%s:%d", a.IP, a.Port)
}

// Address returns a string suitable to dial; prefer returning IP-based
// address, fallback to FQDN
func (a AddrSpec) Address() string {
	if 0 != len(a.IP) {
		return net.JoinHostPort(a.IP.String(), strconv.Itoa(a.Port))
	}
	return net.JoinHostPort(a.FQDN, strconv.Itoa(a.Port))
}

func (a *AddrSpec) BinarySize() int {
	if a == nil {
		return 3 + 4
	}
	if a.FQDN != "" {
		return 3 + 2 + len(a.FQDN)
	}
	if a.IP.To4() != nil {
		return 3 + 4
	}
	if a.IP.To16() != nil {
		return 3 + 16
	}
	return 0
}

func (a *AddrSpec) WriteTo(w io.Writer) (int, error) {
	if a == nil {
		binary.Write(w, binary.BigEndian, AddressIPv4)
		binary.Write(w, binary.BigEndian, []byte{0, 0, 0, 0})
		binary.Write(w, binary.BigEndian, uint16(0))
		return 3 + 4, nil
	}
	if a.FQDN != "" {
		binary.Write(w, binary.BigEndian, AddressDomainName)
		binary.Write(w, binary.BigEndian, len(a.FQDN))
		binary.Write(w, binary.BigEndian, a.FQDN)
		binary.Write(w, binary.BigEndian, uint16(a.Port))
		return 3 + 1 + len(a.FQDN), nil
	}
	if a.IP.To4() != nil {
		binary.Write(w, binary.BigEndian, AddressIPv4)
		binary.Write(w, binary.BigEndian, a.IP.To4())
		binary.Write(w, binary.BigEndian, uint16(a.Port))
		return 3 + 4, nil
	}
	if a.IP.To16() != nil {
		binary.Write(w, binary.BigEndian, AddressIPv6)
		binary.Write(w, binary.BigEndian, a.IP.To16())
		binary.Write(w, binary.BigEndian, uint16(a.Port))
		return 3 + 16, nil
	}
	return 0, fmt.Errorf("failed to format address: %v", a)
}

// A Request represents request received by a server
type Request struct {
	// Protocol version
	Version uint8
	// Requested command
	Command uint8
	// AuthContext provided during negotiation
	AuthContext *AuthContext
	// AddrSpec of the the network that sent the request
	RemoteAddr *AddrSpec
	// AddrSpec of the desired destination
	DestAddr *AddrSpec
	// AddrSpec of the actual destination (might be affected by rewrite)
	realDestAddr *AddrSpec
	bufConn      io.Reader
}

// NewRequest creates a new Request from the tcp connection
func NewRequest(bufConn io.Reader) (*Request, error) {
	// Read the version byte
	header := []byte{0, 0, 0}
	if _, err := io.ReadAtLeast(bufConn, header, 3); err != nil {
		return nil, fmt.Errorf("failed to get command version: %v", err)
	}

	// Ensure we are compatible
	if header[0] != socks5Version {
		return nil, fmt.Errorf("unsupported command version: %v", header[0])
	}

	// Read in the destination address
	dest, err := readAddrSpec(bufConn)
	if err != nil {
		return nil, err
	}

	request := &Request{
		Version:  socks5Version,
		Command:  header[1],
		DestAddr: dest,
		bufConn:  bufConn,
	}

	return request, nil
}

// handleRequest is used for request processing after authentication
func (s *Server) handleRequest(req *Request, conn net.Conn) error {
	ctx := context.Background()

	// Resolve the address if we have a FQDN
	dest := req.DestAddr
	if dest.FQDN != "" {
		_ctx, addr, err := s.config.Resolver.Resolve(ctx, dest.FQDN)
		if err != nil {
			if err := sendReply(conn, ReplyHostUnreachable, nil); err != nil {
				return fmt.Errorf("failed to send reply: %v", err)
			}
			return fmt.Errorf("failed to resolve destination '%v': %v", dest.FQDN, err)
		}
		ctx = _ctx
		dest.IP = addr
	}

	// Apply any address rewrites
	req.realDestAddr = req.DestAddr
	if s.config.Rewriter != nil {
		ctx, req.realDestAddr = s.config.Rewriter.Rewrite(ctx, req)
	}

	// Switch on the command
	switch req.Command {
	case CommandConnect:
		return s.handleConnect(ctx, conn, req)
	case CommandBind:
		return s.handleBind(ctx, conn, req)
	case CommandAssociate:
		return s.handleAssociate(ctx, conn, req)
	default:
		if err := sendReply(conn, ReplyCommandNotSupported, nil); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("unsupported command: %v", req.Command)
	}
}

// handleConnect is used to handle a connect command
func (s *Server) handleConnect(ctx context.Context, conn net.Conn, req *Request) error {
	// Check if this is allowed
	_ctx, ok := s.config.Rules.Allow(ctx, req)
	if !ok {
		if err := sendReply(conn, ReplyRuleFailure, nil); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("connect to %v blocked by rules", req.DestAddr)
	}
	ctx = _ctx

	// Attempt to connect
	dial := s.config.Dial
	if dial == nil {
		dial = func(ctx context.Context, net_, addr string) (net.Conn, error) {
			return net.Dial(net_, addr)
		}
	}
	target, err := dial(ctx, "tcp", req.realDestAddr.Address())
	if err != nil {
		msg := err.Error()
		resp := ReplyHostUnreachable
		if strings.Contains(msg, "refused") {
			resp = ReplyConnectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			resp = ReplyNetworkUnreachable
		}
		if err := sendReply(conn, resp, nil); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("connect to %v failed: %v", req.DestAddr, err)
	}
	defer target.Close()

	// Send success
	if err := sendReply(conn, ReplySucceeded, nil); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}

	// Start proxying
	errCh := make(chan error, 2)
	go proxy(target, req.bufConn, errCh)
	go proxy(conn, target, errCh)

	// Wait
	for i := 0; i < 2; i++ {
		e := <-errCh
		if e != nil {
			// return from this function closes target (and conn).
			return e
		}
	}
	return nil
}

// handleBind is used to handle a connect command
func (s *Server) handleBind(ctx context.Context, conn net.Conn, req *Request) error {
	// Check if this is allowed
	_ctx, ok := s.config.Rules.Allow(ctx, req)
	if !ok {
		if err := sendReply(conn, ReplyRuleFailure, nil); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("bind to %v blocked by rules", req.DestAddr)
	}
	ctx = _ctx

	// TODO: Support bind
	if err := sendReply(conn, ReplyCommandNotSupported, nil); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}
	return nil
}

// handleAssociate is used to handle a connect command
func (s *Server) handleAssociate(ctx context.Context, conn net.Conn, req *Request) error {
	// Check if this is allowed
	_ctx, ok := s.config.Rules.Allow(ctx, req)
	if !ok {
		if err := sendReply(conn, ReplyRuleFailure, nil); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("associate to %v blocked by rules", req.DestAddr)
	}
	ctx = _ctx

	if s.config.BindPort <= 0 {
		if err := sendReply(conn, ReplyCommandNotSupported, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
	}

	// check bindIP 1st
	if len(s.config.BindIP) == 0 || s.config.BindIP.IsUnspecified() {
		s.config.BindIP = net.ParseIP("127.0.0.1")
	}

	bindAddr := AddrSpec{IP: s.config.BindIP, Port: s.config.BindPort}

	if err := sendReply(conn, ReplySucceeded, &bindAddr); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}

	// wait here till the client close the connection
	// check every 10 secs
	tmp := []byte{}
	var neverTimeout time.Time
	for {
		conn.SetReadDeadline(time.Now())
		if _, err := conn.Read(tmp); err == io.EOF {
			break
		} else {
			conn.SetReadDeadline(neverTimeout)
		}
		time.Sleep(10 * time.Second)
	}

	return nil
}

/***********************************
    Requests of client:

    +------+----------+----------+
    | ATYP | DST.ADDR | DST.PORT |
    +------+----------+----------+
    |  1   | Variable |    2     |
    +------+----------+----------+
************************************/

// readAddrSpec is used to read AddrSpec.
// Expects an address type byte, follwed by the address and port
func readAddrSpec(r io.Reader) (*AddrSpec, error) {
	d := &AddrSpec{}

	// Get the address type
	addrType := []byte{0}
	if _, err := r.Read(addrType); err != nil {
		return nil, err
	}

	// Handle on a per type basis
	switch addrType[0] {
	case AddressIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		d.IP = net.IP(addr)

	case AddressIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		d.IP = net.IP(addr)

	case AddressDomainName:
		if _, err := r.Read(addrType); err != nil {
			return nil, err
		}
		addrLen := int(addrType[0])
		fqdn := make([]byte, addrLen)
		if _, err := io.ReadAtLeast(r, fqdn, addrLen); err != nil {
			return nil, err
		}
		d.FQDN = string(fqdn)

	default:
		return nil, errUnrecognizedAddrType
	}

	// Read the port
	port := []byte{0, 0}
	if _, err := io.ReadAtLeast(r, port, 2); err != nil {
		return nil, err
	}
	d.Port = (int(port[0]) << 8) | int(port[1])

	return d, nil
}

// sendReply is used to send a reply message
func sendReply(w io.Writer, resp uint8, addr *AddrSpec) error {
	// Format the message
	buf := bytes.NewBuffer([]byte{socks5Version, resp, 0})
	addr.WriteTo(buf)

	// Send the message
	_, err := w.Write(buf.Bytes())
	return err
}

type closeWriter interface {
	CloseWrite() error
}

// proxy is used to shuffle data from src to destination, and sends errors
// down a dedicated channel
func proxy(dst io.Writer, src io.Reader, errCh chan error) {
	_, err := io.Copy(dst, src)
	if tcpConn, ok := dst.(closeWriter); ok {
		tcpConn.CloseWrite()
	}
	errCh <- err
}
