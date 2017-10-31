package benchmark

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/lucas-clemente/quic-go/integrationtests/tools/testserver"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
)

func TestBenchmark(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecsWithDefaultAndCustomReporters(t, "Benchmark Suite", []Reporter{reporter})
}

var (
	size           int // file size in MB, will be read from flags
	samples        int // number of samples for Measure, will be read from flags
	netemAvailable bool

	reporter       *myReporter
	chromeSession  *gexec.Session
	uploadStarted  chan struct{} // will be closed as soon as the uploadhandler is hit
	uploadFinished chan struct{} // will be clsoed as soon as the upload has finished
)

type networkCondition struct {
	Description string
	Command     string
}

var conditions = []networkCondition{
	{Description: "direct transfer"},
	{Description: "5ms RTT", Command: "tc qdisc add #device root netem delay 2.5ms"},
	{Description: "10ms RTT", Command: "tc qdisc add #device root netem delay 5ms"},
	{Description: "25ms RTT", Command: "tc qdisc add #device root netem delay 12.5ms"},
	{Description: "50ms RTT", Command: "tc qdisc add #device root netem delay 25ms"},
	{Description: "100ms RTT", Command: "tc qdisc add #device root netem delay 50ms"},
	// {Description: "400ms RTT", Command: "tc qdisc add #device root netem delay 200ms"},
	// {Description: "10ms ± 1ms RTT", Command: "tc qdisc add #device root netem delay 5ms 1ms"},
	// {Description: "50ms ± 5ms RTT", Command: "tc qdisc add #device root netem delay 25ms 5ms"},
	// {Description: "10ms RTT, 1% packet loss", Command: "tc qdisc add #device root netem delay 5ms drop 1%"},
	// {Description: "10ms RTT, 5% packet loss", Command: "tc qdisc add #device root netem delay 5ms drop 5%"},
	// {Description: "10ms RTT, 10% packet loss", Command: "tc qdisc add #device root netem delay 5ms drop 10%"},
	// {Description: "50ms RTT, 1% packet loss", Command: "tc qdisc add #device root netem delay 25ms drop 1%"},
	// {Description: "50ms RTT, 5% packet loss", Command: "tc qdisc add #device root netem delay 25ms drop 5%"},
	// {Description: "50ms RTT, 10% packet loss", Command: "tc qdisc add #device root netem delay 25ms drop 10%"},
	// {Description: "100ms RTT, 1% packet loss", Command: "tc qdisc add #device root netem delay 50ms drop 1%"},
	// {Description: "100ms RTT, 5% packet loss", Command: "tc qdisc add #device root netem delay 50ms drop 5%"},
}

func init() {
	flag.IntVar(&size, "size", 40, "data length (in MB)")
	flag.IntVar(&samples, "samples", 1, "number of samples")
	flag.Parse()

	_, err := exec.LookPath("tc")
	netemAvailable = err == nil
	fmt.Println("netemAvailable: ", netemAvailable)

	reporter = &myReporter{}

	// Requires the len & num GET parameters, e.g. /upload?len=100&num=1
	http.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		defer GinkgoRecover()
		response := uploadHTML
		response = strings.Replace(response, "LENGTH", r.URL.Query().Get("len"), -1)
		response = strings.Replace(response, "NUM", r.URL.Query().Get("num"), -1)
		_, err := io.WriteString(w, response)
		Expect(err).NotTo(HaveOccurred())
	})

	http.HandleFunc("/uploadhandler", func(w http.ResponseWriter, r *http.Request) {
		defer GinkgoRecover()
		close(uploadStarted)
		l, err := strconv.Atoi(r.URL.Query().Get("len"))
		Expect(err).NotTo(HaveOccurred())
		defer r.Body.Close()
		actual, err := ioutil.ReadAll(r.Body)
		Expect(err).NotTo(HaveOccurred())
		close(uploadFinished)
		Expect(bytes.Equal(actual, testserver.GeneratePRData(l))).To(BeTrue())
	})
}

func clearNetem() {
	if netemAvailable {
		status := execNetem("tc qdisc show #device")
		if strings.Contains(status, "netem") {
			execNetem("tc qdisc del #device root")
		}
	}
}

func execNetem(cmd string) string {
	fmt.Println("exec", cmd)
	if len(cmd) == 0 {
		return ""
	}
	r := strings.NewReplacer("#device", "dev lo")
	cmd = r.Replace(cmd)
	command := exec.Command("/bin/sh", "-c", "sudo "+cmd)
	session, err := gexec.Start(command, GinkgoWriter, GinkgoWriter)
	Expect(err).ToNot(HaveOccurred())
	Eventually(session).Should(gexec.Exit(0))
	return string(session.Out.Contents())
}

var _ = BeforeSuite(func() {
	clearNetem()
})

var _ = AfterSuite(func() {
	clearNetem()
	reporter.printResult()
})

var _ = BeforeEach(func() {
	testserver.StartQuicServer(nil)
})

var _ = AfterEach(func() {
	testserver.StopQuicServer()
})

func getChromePath() string {
	if runtime.GOOS == "darwin" {
		return "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
	}
	if path, err := exec.LookPath("google-chrome"); err == nil {
		return path
	}
	if path, err := exec.LookPath("chromium-browser"); err == nil {
		return path
	}
	Fail("No Chrome executable found.")
	return ""
}

func chromeTest(version protocol.VersionNumber, url, port string, useQuic bool) {
	userDataDir, err := ioutil.TempDir("", "quic-go-test-chrome-dir")
	Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(userDataDir)
	path := getChromePath()
	var args []string
	if useQuic {
		args = []string{
			"--enable-quic=true",
			"--origin-to-force-quic-on=quic.clemente.io:443",
			fmt.Sprintf("--quic-version=QUIC_VERSION_%s", version.ToAltSvc()),
		}
	}
	args = append(args, []string{
		"--disable-gpu",
		"--no-first-run=true",
		"--no-default-browser-check=true",
		"--user-data-dir=" + userDataDir,
		"--no-proxy-server=true",
		fmt.Sprintf(`--host-resolver-rules=MAP quic.clemente.io:443 127.0.0.1:%s`, port),
		url,
	}...)
	utils.Infof("Running chrome: %s '%s'", getChromePath(), strings.Join(args, "' '"))
	command := exec.Command(path, args...)
	chromeSession, err = gexec.Start(command, nil, nil)
	Expect(err).NotTo(HaveOccurred())
}

const commonJS = `
var buf = new ArrayBuffer(LENGTH);
var prng = new Uint8Array(buf);
var seed = 1;
for (var i = 0; i < LENGTH; i++) {
	// https://en.wikipedia.org/wiki/Lehmer_random_number_generator
	seed = seed * 48271 % 2147483647;
	prng[i] = seed;
}
`

const uploadHTML = `
<html>
<body>
<script>
	console.log("Running DL test...");

  ` + commonJS + `
	for (var i = 0; i < NUM; i++) {
		var req = new XMLHttpRequest();
		req.open("POST", "/uploadhandler?len=" + LENGTH, true);
		req.send(buf);
	}
</script>
</body>
</html>
`
