//go:build !linux

package device

import (
	"github.com/extracomplex/wireguard-go-swgp/conn"
	"github.com/extracomplex/wireguard-go-swgp/rwcancel"
)

func (device *Device) startRouteListener(bind conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
