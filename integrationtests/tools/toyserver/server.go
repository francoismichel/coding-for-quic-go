package toyserver

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	mrand "math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
)

var (
	session    *gexec.Session
	tmpDir     string
	serverPath string
	serverPort int
	cacert     *x509.Certificate
)

func init() {
	_, thisfile, _, ok := runtime.Caller(0)
	if !ok {
		panic("Failed to get current path")
	}
	serverPath = filepath.Join(thisfile, fmt.Sprintf("../../../../../quic-clients/server-%s-debug", runtime.GOOS))
}

// New creates a new server
func New() {
	defer GinkgoRecover()
	var err error
	tmpDir, err = ioutil.TempDir("", "quic-server-certs")
	if err != nil {
		panic(err)
	}
	serverPort = 20000 + int(mrand.Int31n(10000))

	// generate an RSA key pair for the server
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	Expect(err).ToNot(HaveOccurred())

	// save the private key in PKCS8 format to disk (required by quic_server)
	pkcs8key, err := asn1.Marshal(struct { // copied from the x509 package
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{
		PrivateKey: x509.MarshalPKCS1PrivateKey(key),
		Algo: pkix.AlgorithmIdentifier{
			Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1},
			Parameters: asn1.RawValue{Tag: 5},
		},
	})
	Expect(err).ToNot(HaveOccurred())
	f, err := os.Create(filepath.Join(tmpDir, "key.pkcs8"))
	Expect(err).ToNot(HaveOccurred())
	_, err = f.Write(pkcs8key)
	Expect(err).ToNot(HaveOccurred())
	f.Close()

	// generate a Certificate Authority
	// this CA is used to sign the server's key
	// it is set as a valid CA in the QUIC client
	var rootKey *rsa.PrivateKey
	rootKey, cacert = generateCA()
	// generate the server certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-30 * time.Minute),
		NotAfter:     time.Now().Add(30 * time.Minute),
		Subject:      pkix.Name{CommonName: "quic.clemente.io"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, cacert, &key.PublicKey, rootKey)
	Expect(err).ToNot(HaveOccurred())
	// save the certificate to disk
	certOut, err := os.Create(filepath.Join(tmpDir, "cert.pem"))
	Expect(err).ToNot(HaveOccurred())
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certOut.Close()
}

// Port returns the port the server is listening on
func Port() int {
	return serverPort
}

// CACert returns the CA certificate used by the server's cert chain
func CACert() *x509.Certificate {
	return cacert
}

func generateCA() (*rsa.PrivateKey, *x509.Certificate) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	Expect(err).ToNot(HaveOccurred())

	templateRoot := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, templateRoot, templateRoot, &key.PublicKey, key)
	Expect(err).ToNot(HaveOccurred())
	cert, err := x509.ParseCertificate(certDER)
	Expect(err).ToNot(HaveOccurred())
	return key, cert
}

// CreateDownloadFile prepare the file such that it can be by the quic_server
// some HTTP headers neeed to be prepended, see https://www.chromium.org/quic/playing-with-quic
func CreateDownloadFile(filename string, data []byte) {
	dataDir := filepath.Join(tmpDir, "quic.clemente.io")
	err := os.Mkdir(dataDir, 0777)
	Expect(err).ToNot(HaveOccurred())
	f, err := os.Create(filepath.Join(dataDir, filename))
	Expect(err).ToNot(HaveOccurred())
	defer f.Close()
	_, err = f.WriteString("HTTP/1.1 200 OK\n")
	Expect(err).ToNot(HaveOccurred())
	_, err = f.WriteString("Content-Type: text/html\n")
	Expect(err).ToNot(HaveOccurred())
	_, err = f.WriteString(fmt.Sprintf("X-Original-Url: https://quic.clemente.io:%d/%s\n", serverPort, filename))
	Expect(err).ToNot(HaveOccurred())
	_, err = f.WriteString(fmt.Sprintf("Content-Length: %d\n\n", len(data)))
	Expect(err).ToNot(HaveOccurred())
	_, err = f.Write(data)
	Expect(err).ToNot(HaveOccurred())
}

// Start the server
// The download files must be create *before* the quic_server is started
// the quic_server reads its data dir on startup, and only serves those files that were already present then
func Start(version protocol.VersionNumber) {
	command := exec.Command(
		serverPath,
		"--quic_response_cache_dir="+filepath.Join(tmpDir, "quic.clemente.io"),
		"--key_file="+filepath.Join(tmpDir, "key.pkcs8"),
		"--certificate_file="+filepath.Join(tmpDir, "cert.pem"),
		"--quic-version=%s"+version.ToAltSvc(),
		fmt.Sprintf("--port=%d", serverPort),
	)
	var err error
	session, err = gexec.Start(command, nil, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
}

// Stop the server
func Stop() {
	session.Kill()
	Expect(tmpDir).ToNot(BeEmpty())
	err := os.RemoveAll(tmpDir)
	Expect(err).ToNot(HaveOccurred())
}
