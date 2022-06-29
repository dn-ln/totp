package totp

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"math"
	"time"
)

func dynamicTruncate(s string) string {
	var offset uint8 = byte(s[len(s)-1]) & 0xf
	b := []byte{s[offset] & 0x7f, s[offset+1], s[offset+2], s[offset+3]}
	dt := string(b)
	return dt
}

func strToNum(s string) int {
	num := 0
	for i := 0; i < len(s); i++ {
		base := int(s[i])
		shift := int(math.Pow(256, float64(len(s)-1-i)))
		num += int(base * shift)
	}
	return num
}

func modular(num, digits int) string {
	format := fmt.Sprintf("%%0%dd", digits)
	return fmt.Sprintf(format, num%int(math.Pow10(digits)))
}

func GenerateHOTP(k []byte, c [8]byte, h func() hash.Hash, digits int) string {
	hm := hmac.New(h, k)
	if _, err := hm.Write(c[:]); err != nil && err != io.EOF {
		return ""
	}
	checksum := hm.Sum([]byte{})
	dt := dynamicTruncate(string(checksum))
	num := strToNum(dt)
	return modular(num, digits)
}

func timeSteps(t0, t, stepSize int) int {
	return (t - t0) / stepSize
}

func unixTimeSteps(t0, stepSize int) int {
	return timeSteps(t0, int(time.Now().Unix()), stepSize)
}

func counter(timeSteps int) [8]byte {
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], uint64(timeSteps))
	return c
}

func GenerateTOTP(k []byte, h func() hash.Hash, digits int, stepSize int) string {
	steps := unixTimeSteps(0, stepSize)
	c := counter(steps)
	return GenerateHOTP(k, c, h, digits)
}
