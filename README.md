# TOTP Implementation

A practice of simple implementation of TOTP.

## Description
TOTP is an algorithm to generate one-time password based on HOTP.

HOTP is an algorithm based on HMAC. It generates a password with a key and moving factor.<br>In TOTP, the moving factor is defined as the current time steps.

The following is a brief description of the algorithm from [RFC6238](https://datatracker.ietf.org/doc/html/rfc6238#section-4.2) and [RFC4226](https://datatracker.ietf.org/doc/html/rfc4226#section-5.2):
```
TOTP = HOTP(K, T)
HOTP(K, C) = Truncate(HMAC-SHA-1(K, C))
// Please refer to RFC4226 for the definition of Truncate.

K = secret key
C = moving factor
T = (Current Unix time - T0) / X
T0 = the Unix time to start counting time steps (default: 0)
X = time step in seconds (default: 30)
```

## Usage
To run the program:
```
go run .
```
and the output:
```
2022/11/15 18:36:34 Start generating TOTP.
2022/11/15 18:36:39 Your OTP: 751798
2022/11/15 18:36:44 Your OTP: 751798
2022/11/15 18:36:49 Your OTP: 751798
2022/11/15 18:36:54 Your OTP: 751798
2022/11/15 18:36:59 Your OTP: 751798
2022/11/15 18:37:04 Your OTP: 949926
^C2022/11/15 18:37:05 Interrupt received.
```
To change key, digits, and step size, go to `main.go`:
```
totp.GenerateTOTP(key, hash, digits, step)
```
