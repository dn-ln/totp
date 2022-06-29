package totp

import (
	"bytes"
	"crypto/sha512"
	"reflect"
	"testing"
)

func TestDynamicTruncate(t *testing.T) {
	t.Run("\"á\" (0x11100001) to \"a\" (0x01100001)", func(t *testing.T) {
		want := "abcd"

		checksum := bytes.Repeat([]byte("0"), 64)
		var offset uint8 = 8
		checksum[len(checksum)-1] = offset
		checksum[offset] = 'á'
		checksum[offset+1] = want[1]
		checksum[offset+2] = want[2]
		checksum[offset+3] = want[3]
		s := string(checksum)

		got := dynamicTruncate(s)
		if got != want {
			t.Errorf("got %v, want %v", got, want)
		}
	})
	t.Run("\"ý\" (0x11111101) to \"}\" (0x01111101)", func(t *testing.T) {
		want := "}bcd"

		checksum := bytes.Repeat([]byte("0"), 64)
		var offset uint8 = 8
		checksum[len(checksum)-1] = offset
		checksum[offset] = 'ý'
		checksum[offset+1] = want[1]
		checksum[offset+2] = want[2]
		checksum[offset+3] = want[3]
		s := string(checksum)

		got := dynamicTruncate(s)
		if got != want {
			t.Errorf("got %v, want %v", got, want)
		}
	})
}

func TestStrToNum(t *testing.T) {
	t.Run("\"ABCD\" to 1094861636", func(t *testing.T) {
		s := "ABCD"
		want := int(s[3]) + int(s[2])*256 + int(s[1])*256*256 + int(s[0])*256*256*256
		got := strToNum(s)
		if got != want {
			t.Errorf("got %v, want %v", got, want)
		}
	})
}

func TestModular(t *testing.T) {
	t.Run("\"1094061636\" to \"061636\"", func(t *testing.T) {
		num := 1094061636
		digits := 6
		want := "061636"
		got := modular(num, digits)
		if got != want {
			t.Errorf("got %v, want %v", got, want)
		}
	})
}

func TestGenerateHOTP(t *testing.T) {
	t.Run("generate hotp", func(t *testing.T) {
		k := []byte("secret")
		c := [8]byte{0, 0, 0, 0, 0, 0, 0, 97}
		h := sha512.New
		digits := 6
		want := "020088"
		got := GenerateHOTP(k, c, h, digits)
		if got != want {
			t.Errorf("got %v, want %v", got, want)
		}
	})
	t.Run("generate more hotp", func(t *testing.T) {
		k := []byte("secret")
		c := [8]byte{0, 0, 0, 0, 17, 17, 17, 17}
		h := sha512.New
		digits := 6
		want := "325408"
		got := GenerateHOTP(k, c, h, digits)
		if got != want {
			t.Errorf("got %v, want %v", got, want)
		}
	})
}

func TestTimeSteps(t *testing.T) {
	t.Run("test 32 bits \"t1\"", func(t *testing.T) {
		t0 := 0
		t1 := 1257894028
		stepSize := 30
		got := timeSteps(t0, t1, stepSize)
		want := 41929800
		if got != want {
			t.Errorf("got %v, want %v", got, want)
		}
	})
	t.Run("test 64 bits \"t1\"", func(t *testing.T) {
		t0 := 0
		var t1 int64 = 8589934592
		stepSize := 30
		got := timeSteps(t0, int(t1), stepSize)
		want := 286331153
		if got != want {
			t.Errorf("got %v, want %v", got, want)
		}
	})
}

func TestCounter(t *testing.T) {
	steps := 286331153
	got := counter(steps)
	want := [8]byte{0, 0, 0, 0, 17, 17, 17, 17}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}
