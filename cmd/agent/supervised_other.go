//go:build !linux

package main

import (
 "context"
 "errors"
)

func supervisorPipes(_ context.Context,_ context.CancelFunc,enabled bool)(func()error,func(),error){
 if enabled{return nil,func(){},errors.New("supervised worker mode is not supported on this platform")}
 return nil,func(){},nil
}
