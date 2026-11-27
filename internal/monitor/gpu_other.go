//go:build !linux

package monitor

func gpuUsage()float64{return 0}
func gpuNames()[]string{return nil}
