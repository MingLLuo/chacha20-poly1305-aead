# ChaCha20/Poly1305 AEAD

## Building

```bash
make all       # Build chacha20, aead_wrap, and aead_unwrap
make clean
```

## Files

- `code/main.c`: ChaCha20 CLI
- `code/aead_wrap.c`: AEAD encryption CLI
- `code/aead_unwrap.c`: AEAD decryption CLI
- `code/lib/chacha20.c`: ChaCha20 implementation
- `code/lib/poly1305.c`: Poly1305 implementation used by the AEAD toolchain
- `keyfile`: 32-byte test key (00 01 02 ... 1f)
- `sunscreen.txt`: Test plaintext from RFC 8439
