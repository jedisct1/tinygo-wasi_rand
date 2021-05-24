# A CSPRNG for TinyGo/WebAssembly (WASI)

TinyGo doesn't support `crypto/rand` yet, which is quite of a deal breaker for many cryptographic operations.

This module implements `wasi_rand`, a secure random number generator for TinyGo when used in a WebAssembly/WASI environment.

Usage:

```go
import (
    wasi_rand "github.com/jedisct1/tinygo-wasi_rand"
)

func main() {
    var key [32]byte
    if err := wasi_rand.Read(key[:]); err != nil {
        // panic: no entropy source available
    }
}
```

`wasi_rand.Read()` can return any output size.
