package main

import (
	"crypto/sha1"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ad-astra-9t/totp/totp"
)

func main() {
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT)

	tick := time.Tick(time.Second * 5)

	fmt.Println("Start generating TOTP.")
	for {
		select {
		case <-done:
			return
		case t := <-tick:
			password := totp.GenerateTOTP([]byte("my-secret"), sha1.New, 6, 30)
			fmt.Printf("Unix time: %v, Your OTP: %s\n", t.Unix(), password)
		}
	}
}
