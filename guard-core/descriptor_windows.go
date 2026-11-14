//go:build windows

package guardcore

import "errors"

func duplicateTUN(int) (int, error) { return -1, errors.New("Android TUN is unavailable on Windows") }
