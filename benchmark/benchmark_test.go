package benchmark

import (
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"time"

	"github.com/lucas-clemente/quic-go/h2quic"
	_ "github.com/lucas-clemente/quic-go/integrationtests/tools/testlog"
	"github.com/lucas-clemente/quic-go/integrationtests/tools/testserver"
	"github.com/lucas-clemente/quic-go/integrationtests/tools/toyserver"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/testdata"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gexec"
)

func init() {
	var _ = Describe("Benchmarks", func() {
		dataLen := size * /* MB */ 1e6
		data := make([]byte, dataLen)
		rand.Seed(GinkgoRandomSeed())
		rand.Read(data) // no need to check for an error. math.Rand.Read never errors

		BeforeEach(func() {
			uploadStarted = make(chan struct{})
			uploadFinished = make(chan struct{})
		})

		for _, c := range conditions {
			cond := c
			Context(cond.Description, func() {
				BeforeEach(func() {
					if len(cond.Command) > 0 {
						if !netemAvailable {
							Skip("Skipping. netem not found.")
						}
						execNetem(cond.Command)
					}
				})

				AfterEach(func() {
					// TODO: make sure this is always executed
					if len(cond.Command) > 0 && netemAvailable {
						execNetem("tc qdisc del dev lo root")
					}
				})

				Context(fmt.Sprintf("uploading a %d MB file", size), func() {
					Measure(testChromeToTCP, func(b Benchmarker) {
						tlsConf := testdata.GetTLSConfig()
						tlsConf.NextProtos = []string{"h2"}
						srv := &http.Server{
							TLSConfig: tlsConf,
						}
						defer srv.Close()
						addr, err := net.ResolveTCPAddr("tcp", "0.0.0.0:0")
						Expect(err).NotTo(HaveOccurred())
						conn, err := net.ListenTCP("tcp", addr)
						Expect(err).NotTo(HaveOccurred())
						fmt.Printf("%#v\n", conn.Addr())

						go func() {
							defer GinkgoRecover()
							srv.ServeTLS(conn, "", "")
						}()

						go func() {
							defer GinkgoRecover()
							chromeTest(
								protocol.Version39,
								fmt.Sprintf("https://quic.clemente.io:443/upload?num=1&len=%d", dataLen),
								strconv.Itoa(conn.Addr().(*net.TCPAddr).Port),
								false,
							)
						}()

						<-uploadStarted
						runtime := b.Time("transfer time", func() {
							<-uploadFinished
						})

						b.RecordValue(transferRateLabel, float64(dataLen)/1e6/runtime.Seconds())
						chromeSession.Kill()
					}, samples)

					Measure(testChromeToQuicGo, func(b Benchmarker) {
						go func() {
							defer GinkgoRecover()
							chromeTest(
								protocol.Version39,
								fmt.Sprintf("https://quic.clemente.io:443/upload?num=1&len=%d", dataLen),
								testserver.Port(),
								true,
							)
						}()

						<-uploadStarted
						runtime := b.Time("transfer time", func() {
							<-uploadFinished
						})

						b.RecordValue(transferRateLabel, float64(dataLen)/1e6/runtime.Seconds())
						chromeSession.Kill()
					}, samples)

					Measure(testToyServerToClient, func(b Benchmarker) {
						toyserver.New()
						toyserver.CreateDownloadFile("file.dat", data)
						toyserver.Start(protocol.Version39)
						defer toyserver.Stop()
						time.Sleep(500 * time.Millisecond) // give the server some time to start

						command := exec.Command(
							clientPath,
							"--quic-version="+protocol.Version39.ToAltSvc(),
							"--host=127.0.0.1",
							fmt.Sprintf("--port=%d", toyserver.Port()),
							"--disable-certificate-verification",
							"--quiet",
							fmt.Sprintf("https://quic.clemente.io:%d/file.dat", toyserver.Port()),
						)

						session, err := Start(command, nil, GinkgoWriter)
						Expect(err).NotTo(HaveOccurred())
						defer session.Kill()
						defer session.Out.CancelDetects()
						downloadStarted := session.Out.Detect("Connected to 127.0.0.1")
						downloadFinished := session.Out.Detect("Request succeeded")
						Eventually(downloadStarted, time.Second, 10*time.Microsecond).Should(Receive(BeTrue()))
						runtime := b.Time("transfer time", func() {
							Eventually(downloadFinished, 60*time.Second, 100*time.Microsecond).Should(Receive(BeTrue()))
						})
						Eventually(session).Should(Exit(0))
						b.RecordValue(transferRateLabel, float64(dataLen)/1e6/runtime.Seconds())
					}, samples)

					Measure(testQuicGoToQuicGo, func(b Benchmarker) {
						hclient := &http.Client{
							Transport: &h2quic.RoundTripper{},
						}
						done := make(chan struct{})
						go func() {
							defer GinkgoRecover()
							_, err := hclient.Post(
								fmt.Sprintf("https://quic.clemente.io:%s/uploadhandler?len=%d", testserver.Port(), dataLen),
								"multiplart/form-data",
								bytes.NewReader(testserver.GeneratePRData(dataLen)),
							)
							Expect(err).ToNot(HaveOccurred())
							close(done)
						}()
						<-uploadStarted
						runtime := b.Time("transfer time", func() {
							<-uploadFinished
							time.Sleep(100 * time.Millisecond)
						})
						b.RecordValue(transferRateLabel, float64(dataLen)/1e6/runtime.Seconds())
						<-done
					}, samples)
				})
			})
		}
	})
}
