package crypto

import (
	"crypto"
	"encoding/binary"

	"github.com/bifurcation/mint"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

const (
	clientExporterLabel = "EXPORTER-QUIC client 1rtt"
	serverExporterLabel = "EXPORTER-QUIC server 1rtt"
)

// A TLSExporter gets the negotiated ciphersuite and computes exporter
type TLSExporter interface {
	GetCipherSuite() mint.CipherSuiteParams
	ComputeExporter(label string, context []byte, keyLength int) ([]byte, error)
}

func qhkdfExpand(secret []byte, label string, length int) []byte {
	qlabel := make([]byte, 2+1+5+len(label))
	binary.BigEndian.PutUint16(qlabel[0:2], uint16(length))
	qlabel[2] = uint8(5 + len(label))
	copy(qlabel[3:], []byte("QUIC "+label))
	return mint.HkdfExpand(crypto.SHA256, secret, qlabel, length)
}

type updatableAEAD struct {
	AEAD

	exporter TLSExporter

	ourSecret   string
	theirSecret string
}

var _ UpdatableAEAD = &updatableAEAD{}

// NewUpdatableAEAD gets the 1-RTT AEAD needed for IETF QUIC
func NewUpdatableAEAD(exporter TLSExporter, pers protocol.Perspective) (UpdatableAEAD, error) {
	var ourLabel, theirLabel string
	if pers == protocol.PerspectiveClient {
		ourLabel = clientExporterLabel
		theirLabel = serverExporterLabel
	} else {
		ourLabel = serverExporterLabel
		theirLabel = clientExporterLabel
	}
	return (&updatableAEAD{
		exporter:    exporter,
		ourSecret:   ourLabel,
		theirSecret: theirLabel,
	}).Next()
}

func (h *updatableAEAD) Next() (UpdatableAEAD, error) {
	ourSecret, ourKey, ourIV, err := h.computeKeyAndIV(h.ourSecret)
	if err != nil {
		return nil, err
	}
	theirSecret, theirKey, theirIV, err := h.computeKeyAndIV(h.theirSecret)
	if err != nil {
		return nil, err
	}
	aead, err := NewAEADAESGCM(theirKey, ourKey, theirIV, ourIV)
	if err != nil {
		return nil, err
	}
	return &updatableAEAD{
		AEAD:        aead,
		exporter:    h.exporter,
		ourSecret:   string(ourSecret),
		theirSecret: string(theirSecret),
	}, nil
}

func (h *updatableAEAD) computeKeyAndIV(label string) (secret, key, iv []byte, err error) {
	cs := h.exporter.GetCipherSuite()
	secret, err = h.exporter.ComputeExporter(label, nil, cs.Hash.Size())
	if err != nil {
		return nil, nil, nil, err
	}
	key = qhkdfExpand(secret, "key", cs.KeyLen)
	iv = qhkdfExpand(secret, "iv", cs.IvLen)
	return secret, key, iv, nil
}
