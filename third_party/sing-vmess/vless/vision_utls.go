//go:build with_utls

package vless

import (
	"net"
	"reflect"
	"unsafe"

	utls "github.com/metacubex/utls"
	"github.com/sagernet/sing/common"

	"github.com/xtls/reality"
)

func init() {
	tlsRegistry = append(tlsRegistry, func(conn net.Conn) (loaded bool, netConn net.Conn, reflectType reflect.Type, reflectPointer unsafe.Pointer) {
		tlsConn, loaded := common.Cast[*reality.Conn](conn)
		if loaded {
			return true, tlsConn.NetConn(), reflect.TypeOf(tlsConn).Elem(), unsafe.Pointer(tlsConn)
		}
		return
	})
	// sing-box 1.13 serves REALITY with metacubex/utls, so a REALITY
	// connection reaches Vision as a *utls.Conn. Only xtls/reality was known
	// here, and every VLESS REALITY Vision user was refused with "vision: not
	// a valid supported TLS connection". The same two types upstream
	// sing-vmess registers.
	tlsRegistry = append(tlsRegistry, func(conn net.Conn) (loaded bool, netConn net.Conn, reflectType reflect.Type, reflectPointer unsafe.Pointer) {
		uConn, loaded := common.Cast[*utls.UConn](conn)
		if loaded {
			return true, uConn.NetConn(), reflect.TypeOf(uConn.Conn).Elem(), unsafe.Pointer(uConn.Conn)
		}
		tlsConn, loaded := common.Cast[*utls.Conn](conn)
		if loaded {
			return true, tlsConn.NetConn(), reflect.TypeOf(tlsConn).Elem(), unsafe.Pointer(tlsConn)
		}
		return
	})
}
