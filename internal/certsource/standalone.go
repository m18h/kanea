package certsource

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// StandaloneValidity is the init-provisioned API/dashboard listener pair's
// lifetime (PRD v1.80): a static, self-signed certificate and key that
// `kanea init` mints once and the daemon serves in `provided` mode, so a
// public listen address is no longer refused for want of a certificate.
// kanea.hcl's bind stanza (api_tls's managed modes) and explicit
// --listen-cert/--listen-key flags stay ahead of it in precedence.
const StandaloneValidity = 10 * 365 * 24 * time.Hour

// StandalonePairPEM mints a single-host self-signed certificate with no CA.
// An IP-shaped host becomes an IP SAN, not a DNS SAN: clients match the two
// differently, and a dashboard reached at a bare address needs the former
// (the v1.61 rule, applied to the init-provisioned pair). A name becomes a
// DNS SAN. An empty host is refused: a SAN needs something to name.
func StandalonePairPEM(host string, now time.Time) (certPEM, keyPEM []byte, err error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, nil, errors.New("certsource: a standalone pair needs a host to name")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	var dnsNames []string
	var ipAddrs []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ipAddrs = []net.IP{ip}
	} else {
		dnsNames = []string{host}
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-clockSkewAllowance),
		NotAfter:     now.Add(StandaloneValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ipAddrs,
	}
	// Self-signed: the template is its own parent, signed by its own key.
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("sign standalone certificate: %w", err)
	}
	keyStr, err := encodeECKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return certPEM, []byte(keyStr), nil
}
