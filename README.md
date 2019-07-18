# A QUIC implementation in pure Go

<img src="docs/quic.png" width=303 height=124>

[![Godoc Reference](https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square)](https://godoc.org/github.com/lucas-clemente/quic-go)
[![Travis Build Status](https://img.shields.io/travis/lucas-clemente/quic-go/master.svg?style=flat-square&label=Travis+build)](https://travis-ci.org/lucas-clemente/quic-go)
[![CircleCI Build Status](https://img.shields.io/circleci/project/github/lucas-clemente/quic-go.svg?style=flat-square&label=CircleCI+build)](https://circleci.com/gh/lucas-clemente/quic-go)
[![Windows Build Status](https://img.shields.io/appveyor/ci/lucas-clemente/quic-go/master.svg?style=flat-square&label=windows+build)](https://ci.appveyor.com/project/lucas-clemente/quic-go/branch/master)
[![Code Coverage](https://img.shields.io/codecov/c/github/lucas-clemente/quic-go/master.svg?style=flat-square)](https://codecov.io/gh/lucas-clemente/quic-go/)
[![fuzzit](https://app.fuzzit.dev/badge?org_id=quic-go&branch=master)](https://fuzzit.dev)

quic-go is an implementation of the [QUIC](https://en.wikipedia.org/wiki/QUIC) protocol in Go. It roughly implements the [IETF QUIC draft](https://github.com/quicwg/base-drafts), although we don't fully support any of the draft versions at the moment.

## FEC Extension

This fork propose a *simple* Forward Erasure Correction (FEC) extension as proposed in the current [Coding for QUIC IRTF draft](https://tools.ietf.org/html/draft-swett-nwcrg-coding-for-quic-03).
It currently implements the third version of the draft, except the negociation process.
Two block error correcting codes are currently proposed: XOR and Reed-Solomon. A sliding-window RLC code is on the way.
This work is a refactor of our previous implementation [presented during the IFIP Networking 2019 conference](https://dial.uclouvain.be/pr/boreal/fr/object/boreal%3A217933). This version is currently simpler than the previous version, but aims at staying as up-to-date as possible with both the IRTF draft version and the upstream quic-go implementation, this is why we want to keep a rather simple code. Of course, contributions are welcome.

### FEC-enabled HTTP/3 communication
You will find an example of an FEC-enabled HTTP/3 server and client in the `example-fec/mail.go` file.

To run a FEC-enabled server that will send Reed-Solomon-encoded REPAIR frames, run :

		go run example-fec/main.go -s -p port_to_listen_to -fec -fecScheme rs
		
To run a FEC-enabled client that will send XOR-encoded REPAIR frames (and decode the Reed-Solomon-encoded REPAIR frames sent by the server), run :

		go run example-fec/main.go -fec -fecScheme rs https://server_address:port/resource_path

You can read the code of this example to better understand how to configure a QUIC session using FEC.

## Version compatibility

Since quic-go is under active development, there's no guarantee that two builds of different commits are interoperable. The QUIC version used in the *master* branch is just a placeholder, and should not be considered stable.

If you want to use quic-go as a library in other projects, please consider using a [tagged release](https://github.com/lucas-clemente/quic-go/releases). These releases expose [experimental QUIC versions](https://github.com/quicwg/base-drafts/wiki/QUIC-Versions), which are guaranteed to be stable.

## Google QUIC

quic-go used to support both the QUIC versions supported by Google Chrome and QUIC as deployed on Google's servers, as well as IETF QUIC. Due to the divergence of the two protocols, we decided to not support both versions any more.

The *master* branch **only** supports IETF QUIC. For Google QUIC support, please refer to the [gquic branch](https://github.com/lucas-clemente/quic-go/tree/gquic). 

## Guides

We currently support Go 1.12+, with [Go modules](https://github.com/golang/go/wiki/Modules) support enabled.

Installing and updating dependencies:

    go get -u ./...

Running tests:

    go test ./...

### QUIC without HTTP/3

Take a look at [this echo example](example/echo/echo.go).

## Usage

### As a server

See the [example server](example/main.go). Starting a QUIC server is very similar to the standard lib http in go:

```go
http.Handle("/", http.FileServer(http.Dir(wwwDir)))
http3.ListenAndServeQUIC("localhost:4242", "/path/to/cert/chain.pem", "/path/to/privkey.pem", nil)
```

### As a client

See the [example client](example/client/main.go). Use a `http3.RoundTripper` as a `Transport` in a `http.Client`.

```go
http.Client{
  Transport: &http3.RoundTripper{},
}
```

## Contributing

We are always happy to welcome new contributors! We have a number of self-contained issues that are suitable for first-time contributors, they are tagged with [help wanted](https://github.com/lucas-clemente/quic-go/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22). If you have any questions, please feel free to reach out by opening an issue or leaving a comment.
