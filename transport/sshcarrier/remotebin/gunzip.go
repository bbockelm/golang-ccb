//go:build embedremote

package remotebin

import (
	"bytes"
	"compress/gzip"
	"io"
)

func gunzip(body []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	return io.ReadAll(r)
}
