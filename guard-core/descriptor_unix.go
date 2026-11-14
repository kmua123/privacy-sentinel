//go:build !windows

package guardcore

import "syscall"

func duplicateTUN(fd int) (int, error) { return syscall.Dup(fd) }
