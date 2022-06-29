package main

import (
	"crypto/sha1"
	"fmt"

	"github.com/ad-astra-9t/totp/totp"
)

func main() {
	password := totp.GenerateTOTP([]byte("my-secret"), sha1.New, 6, 30)
	fmt.Printf("Your OTP: %s\n", password)
}
