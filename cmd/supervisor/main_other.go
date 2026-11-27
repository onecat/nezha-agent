//go:build !linux

package main
import "log"
func main(){log.Fatal("managed upgrade supervisor is Linux-only")}
