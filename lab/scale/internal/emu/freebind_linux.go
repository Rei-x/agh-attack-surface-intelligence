//go:build linux

package emu

import "syscall"

func freebind(fd uintptr) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_FREEBIND, 1)
}
