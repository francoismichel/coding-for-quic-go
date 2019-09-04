package main

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/lucas-clemente/quic-go/integrationtests/tools/testserver"
	"github.com/lucas-clemente/quic-go/internal/testdata"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/quictrace"
)

type binds []string

func (b binds) String() string {
	return strings.Join(b, ",")
}

func (b *binds) Set(v string) error {
	*b = strings.Split(v, ",")
	return nil
}

// Size is needed by the /demo/upload handler to determine the size of the uploaded file
type Size interface {
	Size() int64
}

var tracer quictrace.Tracer

func init() {
	tracer = quictrace.NewTracer()
}

func exportTraces() error {
	traces := tracer.GetAllTraces()
	if len(traces) != 1 {
		return errors.New("expected exactly one trace")
	}
	for _, trace := range traces {
		f, err := os.Create("trace.qtr")
		if err != nil {
			return err
		}
		if _, err := f.Write(trace); err != nil {
			return err
		}
		f.Close()
		fmt.Println("Wrote trace to", f.Name())
	}
	return nil
}

type tracingHandler struct {
	handler http.Handler
}

var _ http.Handler = &tracingHandler{}

func (h *tracingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.handler.ServeHTTP(w, r)
	if err := exportTraces(); err != nil {
		panic(err)
	}
}

func setupHandler(www string, trace bool) http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/", http.FileServer(http.Dir(www)))
	mux.HandleFunc("/demo/tile", func(w http.ResponseWriter, r *http.Request) {
		// Small 40x40 png
		w.Write([]byte{
			0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
			0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x28,
			0x01, 0x03, 0x00, 0x00, 0x00, 0xb6, 0x30, 0x2a, 0x2e, 0x00, 0x00, 0x00,
			0x03, 0x50, 0x4c, 0x54, 0x45, 0x5a, 0xc3, 0x5a, 0xad, 0x38, 0xaa, 0xdb,
			0x00, 0x00, 0x00, 0x0b, 0x49, 0x44, 0x41, 0x54, 0x78, 0x01, 0x63, 0x18,
			0x61, 0x00, 0x00, 0x00, 0xf0, 0x00, 0x01, 0xe2, 0xb8, 0x75, 0x22, 0x00,
			0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
		})
	})

	mux.HandleFunc("/demo/tiles", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<html><head><style>img{width:40px;height:40px;}</style></head><body>")
		for i := 0; i < 200; i++ {
			fmt.Fprintf(w, `<img src="/demo/tile?cachebust=%d">`, i)
		}
		io.WriteString(w, "</body></html>")
	})

	mux.HandleFunc("/demo/echo", func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			fmt.Printf("error reading body while handling /echo: %s\n", err.Error())
		}
		w.Write(body)
	})

	// accept file uploads and return the MD5 of the uploaded file
	// maximum accepted file size is 1 GB
	mux.HandleFunc("/demo/upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			err := r.ParseMultipartForm(1 << 30) // 1 GB
			if err == nil {
				var file multipart.File
				file, _, err = r.FormFile("uploadfile")
				if err == nil {
					var size int64
					if sizeInterface, ok := file.(Size); ok {
						size = sizeInterface.Size()
						b := make([]byte, size)
						file.Read(b)
						md5 := md5.Sum(b)
						fmt.Fprintf(w, "%x", md5)
						return
					}
					err = errors.New("couldn't get uploaded file size")
				}
			}
			if err != nil {
				utils.DefaultLogger.Infof("Error receiving upload: %#v", err)
			}
		}
		io.WriteString(w, `<html><body><form action="/demo/upload" method="post" enctype="multipart/form-data">
				<input type="file" name="uploadfile"><br>
				<input type="submit">
			</form></body></html>`)
	})

	http.HandleFunc("/dynamic/", func(w http.ResponseWriter, r *http.Request) {
		const maxSize = 1 << 30 // 1 GB
		num, err := strconv.ParseInt(strings.ReplaceAll(r.RequestURI, "/dynamic/", ""), 10, 64)
		if err != nil || num <= 0 || num > maxSize {
			w.WriteHeader(400)
			return
		}
		w.Write(testserver.GeneratePRData(int(num)))
	})

	if !trace {
		return mux
	}
	return &tracingHandler{handler: mux}
}

var elapsed time.Duration


func client(quicConf *quic.Config, quiet bool, insecure bool, urls []string) {

	logger := utils.DefaultLogger


	roundTripper := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			RootCAs:            testdata.GetRootCA(),
			InsecureSkipVerify: insecure,
		},
		QuicConfig: quicConf,
	}
	defer roundTripper.Close()
	hclient := &http.Client{
		Transport: roundTripper,
	}

	var wg sync.WaitGroup
	wg.Add(len(urls))
	for _, addr := range urls {
		logger.Infof("GET %s", addr)
		go func(addr string) {
			rsp, err := hclient.Get(addr)
			if err != nil {
				panic(err)
			}
			logger.Infof("Got response for %s: %#v", addr, rsp)

			body := &bytes.Buffer{}
			_, err = io.Copy(body, rsp.Body)
			if err != nil {
				panic(err)
			}
			elapsed = time.Now().Sub(started)
			if quiet {
				logger.Infof("Request Body: %d bytes", body.Len())
			} else {
				logger.Infof("Request Body:")
				logger.Infof("%s", body.Bytes())
			}
			wg.Done()
		}(addr)
	}
	wg.Wait()
	log.Printf("%+v ms", elapsed.Seconds()*1000)
}


func server(bs binds, tcp bool, quicConf *quic.Config, handler http.Handler) {
	var wg sync.WaitGroup
	wg.Add(len(bs))
	for _, b := range bs {
		bCap := b
		go func() {
			var err error
			if tcp {
				certFile, keyFile := testdata.GetCertificatePaths()
				err = http3.ListenAndServe(bCap, certFile, keyFile, nil)
			} else {
				server := http3.Server{
					Server:     &http.Server{Handler: handler, Addr: bCap},
					QuicConfig: quicConf,
				}
				err = server.ListenAndServeTLS(testdata.GetCertificatePaths())
			}
			if err != nil {
				fmt.Println(err)
			}
			wg.Done()
		}()
	}
	wg.Wait()
}

type MyLogger struct {
	utils.Logger
}
var checkpoint bool
var started time.Time
func (l *MyLogger) Debugf(format string, args ...interface{}) {
	if !checkpoint {
		if strings.Contains(format, "Installed 1-RTT Write") {
			checkpoint = true
			started = time.Now()
		}
	}
	l.Logger.Debugf(format, args...)
}
func (l *MyLogger) WithPrefix(prefix string) utils.Logger {
	return &MyLogger{
		l.Logger.WithPrefix(prefix),
	}
}

func main() {
	// defer profile.Start().Stop()
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
	// runtime.SetBlockProfileRate(1)

	verbose := flag.Bool("v", false, "verbose")
	bs := binds{}
	flag.Var(&bs, "bind", "bind to")
	s := flag.Bool("s", false, "if present, act as a server")
	port := flag.Int("p", 6121, "port to listen to if -s is set")
	www := flag.String("www", "/var/www", "www data")
	tcp := flag.Bool("tcp", false, "also listen on TCP")
	trace := flag.Bool("trace", false, "enable quic-trace")
	fec := flag.Bool("fec", false, "enable FEC")
	fecScheme := flag.String("fecScheme", "", "specifies the FEC Scheme to use when FEC is enabled (currently only 'xor' and 'rs')")
	quiet := flag.Bool("q", false, "don't print the data")
	insecure := flag.Bool("insecure", false, "skip certificate verification")
	flag.Parse()
	urls := flag.Args()

	logger := &MyLogger{utils.DefaultLogger}

	if *verbose {
		logger.SetLogLevel(utils.LogLevelDebug)
	} else if *quiet {
		logger.SetLogLevel(utils.LogLevelError)
	} else {
		logger.SetLogLevel(utils.LogLevelInfo)
	}
	logger.SetLogTimeFormat("")

	utils.DefaultLogger = logger

	if len(bs) == 0 {
		bs = binds{fmt.Sprintf("0.0.0.0:%d", *port)}
	}

	handler := setupHandler(*www, *trace)
	var quicConf= &quic.Config{}
	if *trace {
		quicConf = &quic.Config{QuicTracer: tracer}
	}
	if *fec {
		switch *fecScheme{
		case "xor":
			quicConf.FECSchemeID = protocol.XORFECScheme
		case "rs":
			quicConf.FECSchemeID = protocol.ReedSolomonFECScheme

		}
	}

	if *s {
		server(bs, *tcp, quicConf, handler)
	} else {
		client(quicConf, *quiet, *insecure, urls)
	}
}