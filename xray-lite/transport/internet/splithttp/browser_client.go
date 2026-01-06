package splithttp

import (
	"context"
	"io"
	gonet "net"

	"github.com/xtls/xray-core/common/errors"
)

// BrowserDialerClient implements splithttp.DialerClient in terms of browser dialer
// NOTE: Browser dialer has been removed for binary size reduction (Phase XL.3)
type BrowserDialerClient struct {
	transportConfig *Config
}

func (c *BrowserDialerClient) IsClosed() bool {
	return true // Browser dialer is disabled
}

func (c *BrowserDialerClient) OpenStream(ctx context.Context, url string, body io.Reader, uploadOnly bool) (io.ReadCloser, gonet.Addr, gonet.Addr, error) {
	return nil, nil, nil, errors.New("browser dialer has been removed for binary size reduction")
}

func (c *BrowserDialerClient) PostPacket(ctx context.Context, url string, body io.Reader, contentLength int64) error {
	return errors.New("browser dialer has been removed for binary size reduction")
}
