//go:build !linux

package emu

func freebind(fd uintptr) error { return nil }
