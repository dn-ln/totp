package main

import (
	"crypto/sha1"
	"log"
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

	log.Println("Start generating TOTP.")
	for {
		select {
		case <-done:
			log.Println("Interrupt received.")
			return
		case <-tick:
			password := totp.GenerateTOTP([]byte("my-secret"), sha1.New, 6, 30)
			log.Printf("Your OTP: %s\n", password)
		}
	}
}
