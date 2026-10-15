package anytls

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"os"

	"github.com/anytls/sing-anytls/padding"
	"github.com/anytls/sing-anytls/session"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type Service struct {
	users                       atomic.TypedValue[map[[32]byte]string]
	authenticatedSessionHandler atomic.TypedValue[func(context.Context, net.Conn) (func(), error)]
	padding                     atomic.TypedValue[*padding.PaddingFactory]
	handler                     N.TCPConnectionHandlerEx
	fallbackHandler             N.TCPConnectionHandlerEx
	logger                      logger.ContextLogger
}

type ServiceConfig struct {
	PaddingScheme   []byte
	Users           []User
	Handler         N.TCPConnectionHandlerEx
	FallbackHandler N.TCPConnectionHandlerEx
	Logger          logger.ContextLogger
}

type User struct {
	Name     string
	Password string
}

func NewService(config ServiceConfig) (*Service, error) {
	service := &Service{
		handler:         config.Handler,
		fallbackHandler: config.FallbackHandler,
		logger:          config.Logger,
	}

	if service.handler == nil || service.logger == nil {
		return nil, os.ErrInvalid
	}

	service.UpdateUsers(config.Users)

	if !padding.UpdatePaddingScheme(config.PaddingScheme, &service.padding) {
		return nil, errors.New("incorrect padding scheme format")
	}

	return service, nil
}

func (s *Service) UpdateUsers(users []User) {
	u := make(map[[32]byte]string)
	for _, user := range users {
		u[sha256.Sum256([]byte(user.Password))] = user.Name
	}
	// Publish a complete immutable table. Authentication must never observe
	// a map being published concurrently with a panel user update.
	s.users.Store(u)
}

// SetAuthenticatedSessionHandler installs an optional physical-session observer.
// The handler may refuse a user generation removed during authentication and
// returns cleanup that runs when the session ends, including an idle session.
func (s *Service) SetAuthenticatedSessionHandler(handler func(context.Context, net.Conn) (func(), error)) {
	s.authenticatedSessionHandler.Store(handler)
}

// NewConnection `conn` should be plaintext
func (s *Service) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	sessionConn := conn
	b := buf.NewPacket()
	defer b.Release()

	n, err := b.ReadOnceFrom(conn)
	if err != nil {
		return err
	}
	conn = bufio.NewCachedConn(conn, b)

	by, err := b.ReadBytes(32)
	if err != nil {
		b.Resize(0, n)
		return s.fallback(ctx, conn, source, err, onClose)
	}
	var passwordSha256 [32]byte
	copy(passwordSha256[:], by)
	if user, ok := s.users.Load()[passwordSha256]; ok {
		ctx = auth.ContextWithUser(ctx, user)
	} else {
		b.Resize(0, n)
		return s.fallback(ctx, conn, source, E.New("unknown user password"), onClose)
	}
	by, err = b.ReadBytes(2)
	if err != nil {
		b.Resize(0, n)
		return s.fallback(ctx, conn, source, E.Extend(err, "read padding length"), onClose)
	}
	paddingLen := binary.BigEndian.Uint16(by)
	if paddingLen > 0 {
		_, err = b.ReadBytes(int(paddingLen))
		if err != nil {
			b.Resize(0, n)
			return s.fallback(ctx, conn, source, E.Extend(err, "read padding"), onClose)
		}
	}
	if handler := s.authenticatedSessionHandler.Load(); handler != nil {
		cleanup, err := handler(ctx, sessionConn)
		if err != nil {
			return err
		}
		if cleanup != nil {
			defer cleanup()
		}
	}

	session := session.NewServerSession(conn, func(stream *session.Stream) {
		// Acknowledge the stream now, not once the destination is dialled.
		// A v2 client reusing a pooled session closes it unless the SYNACK
		// arrives within three seconds of opening the stream. Sent after the
		// dial, the acknowledgement waited on sniffing, DNS and the
		// destination's own latency on top of the round trip, so slow sites
		// and lossy links killed healthy sessions. Liveness is what the client
		// checks; a dial that fails still closes the stream with FIN.
		_ = stream.HandshakeSuccess()
		destination, err := M.SocksaddrSerializer.ReadAddrPort(stream)
		if err != nil {
			s.logger.ErrorContext(ctx, "ReadAddrPort:", err)
			// Nothing else will ever close it: the client would wait on a
			// stream the server has abandoned.
			_ = stream.Close()
			return
		}

		s.handler.NewConnectionEx(ctx, stream, source, destination, onClose)
	}, &s.padding, s.logger)
	session.Run()
	session.Close()
	return nil
}

func (s *Service) fallback(ctx context.Context, conn net.Conn, source M.Socksaddr, err error, onClose N.CloseHandlerFunc) error {
	if s.fallbackHandler == nil {
		return E.Extend(err, "fallback disabled")
	}
	s.fallbackHandler.NewConnectionEx(ctx, conn, source, M.Socksaddr{}, onClose)
	return nil
}
