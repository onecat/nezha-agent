//go:build !linux

package main

import("context";"errors")
func serviceCommand([]string)error{return errors.New("service installation supports Linux amd64")}
func isDirectConfig(string)bool{return false}
func runDirect(context.Context,string)error{return errors.New("unsupported platform")}
