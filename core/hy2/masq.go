package hy2

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/apernet/hysteria/extras/v2/correctnet"
	"github.com/apernet/hysteria/extras/v2/masq"
	"go.uber.org/zap"
)

// masqTCP serves the TCP side of a node's masquerade (plain HTTP and HTTPS),
// and - unlike hysteria's own masq.MasqTCPServer, which it reproduces - can be
// stopped. That one has no Close: a node reload left the old listeners holding
// the ports, the new node's bind failed, and the failure was logged with
// Fatal, ending the process and every node it served.
type masqTCP struct {
	servers []*http.Server
}

// startMasqTCP binds both listeners before returning, so a port that is taken
// fails the node's start instead of surfacing later on a goroutine.
func startMasqTCP(s *masq.MasqTCPServer, httpAddr, httpsAddr string, logger *zap.Logger) (*masqTCP, error) {
	m := &masqTCP{}
	serve := func(addr string, srv *http.Server, tlsOn bool) error {
		ln, err := correctnet.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("masquerade listen %s: %w", addr, err)
		}
		m.servers = append(m.servers, srv)
		go func() {
			var err error
			if tlsOn {
				logger.Info("masquerade HTTPS server up and running", zap.String("listen", addr))
				err = srv.ServeTLS(ln, "", "")
			} else {
				logger.Info("masquerade HTTP server up and running", zap.String("listen", addr))
				err = srv.Serve(ln)
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("masquerade server stopped", zap.String("listen", addr), zap.Error(err))
			}
		}()
		return nil
	}
	if httpAddr != "" {
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if s.ForceHTTPS {
				if s.HTTPSPort == 0 || s.HTTPSPort == 443 {
					// Omit port if it's the default
					http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
				} else {
					http.Redirect(w, r, fmt.Sprintf("https://%s:%d%s", r.Host, s.HTTPSPort, r.RequestURI), http.StatusMovedPermanently)
				}
				return
			}
			s.Handler.ServeHTTP(altSvcWriter(w, s.QUICPort), r)
		})}
		if err := serve(httpAddr, srv, false); err != nil {
			return nil, err
		}
	}
	if httpsAddr != "" {
		srv := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				s.Handler.ServeHTTP(altSvcWriter(w, s.QUICPort), r)
			}),
			TLSConfig: s.TLSConfig,
		}
		if err := serve(httpsAddr, srv, true); err != nil {
			_ = m.Close()
			return nil, err
		}
	}
	return m, nil
}

// Close stops the servers and releases their ports.
func (m *masqTCP) Close() error {
	var errs []error
	for _, srv := range m.servers {
		if err := srv.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// altSvcWriter advertises the node's QUIC port in Alt-Svc on every response,
// whatever the handler set, as hysteria's masquerade server does.
func altSvcWriter(w http.ResponseWriter, port int) http.ResponseWriter {
	a := &altSvcResponseWriter{ResponseWriter: w, port: port}
	if _, ok := w.(http.Hijacker); ok {
		return &altSvcHijacker{a} // WebSocket upgrades need Hijack
	}
	return a
}

type altSvcResponseWriter struct {
	http.ResponseWriter
	port int
}

func (w *altSvcResponseWriter) WriteHeader(statusCode int) {
	w.Header().Set("Alt-Svc", fmt.Sprintf(`h3=":%d"; ma=2592000`, w.port))
	w.ResponseWriter.WriteHeader(statusCode)
}

type altSvcHijacker struct {
	*altSvcResponseWriter
}

func (w *altSvcHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.ResponseWriter.(http.Hijacker).Hijack()
}
