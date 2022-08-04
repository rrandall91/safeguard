# Safeguard

[![GoDoc](https://godoc.org/github.com/rrandall91/safeguard?status.svg)](https://godoc.org/github.com/rrandall91/safeguard)
[![Go Report Card](https://goreportcard.com/badge/github.com/rrandall91/safeguard)](https://goreportcard.com/report/github.com/rrandall91/safeguard)
[![Maintainability](https://api.codeclimate.com/v1/badges/caf328948608ea19525b/maintainability)](https://codeclimate.com/github/rrandall91/safeguard/maintainability)
[![Tests](https://github.com/rrandall91/safeguard/actions/workflows/test.yml/badge.svg)](https://github.com/rrandall91/safeguard/actions/workflows/test.yml)
[![Test Coverage](https://api.codeclimate.com/v1/badges/caf328948608ea19525b/test_coverage)](https://codeclimate.com/github/rrandall91/safeguard/test_coverage)

Safeguard is a lightweight wrapper library designed to provide simple helper function for implementing industry standard hashing and encryption using the SHA256 and AES-GCM algorithms, respectively.

## Features

* Simple wrapper for handling AES-GCM encryption and decryption
* Simple wrapper for handling SHA256 hashing
* No dependencies (only uses the Go standard library)

## Usage

```go
package main

import (
    "github.com/rrandall91/safeguard"
)

func main() {
    c := safeguard.Config{
        // 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256
        EncryptionKey: "oAKLlH2T0wSAfMyUaUQTGXBhBjXZUp5I",
    }

    s := safeguard.New(&c)

    s.Hash("Hello World")
    // a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e

    s.Encrypt("Hello World")
    // mZ/h+rTwNfUJIflKjG9rt3TxmkbtarXpgVWnZzR62/ZeLJ4O+hFe

    s.Decrypt("mZ/h+rTwNfUJIflKjG9rt3TxmkbtarXpgVWnZzR62/ZeLJ4O+hFe")
    // Hello World
}
```

## License

Copyright (c) 2022-present [Rashaad Randall](https://github.com/rrandall91). Safeguard is free and open-source software licensed under the [GNU Affero General Public License](https://github.com/rrandall91/safeguard/blob/master/LICENSE).