# MineTunnel_camellia_encryptor
The encryption plugin for [MineTunnel](https://github.com/MastMind/MineTunnel "MineTunnel repo").
Camellia-128/192/256-CBC (PKCS7 padding) with optional message
authentication: CMAC-Camellia and/or HMAC-SHA256 tags are appended to the
ciphertext. The key size is selected automatically from the length of the
`key` hex string.

# Build and requirements
rustc 1.95.0-nightly or higher is recommended.
The plugin is built automatically by the MineTunnel build system
(`MineTunnel_build/build.py`) for all targets.

# How to use it
The result as `.so` file can be attached to MineTunnel as encryption plugin (More detailed [here](https://github.com/MastMind/MineTunnel "MineTunnel repo") chapter "Encryption").

# Format of encryption_params JSON

```
encryption_params : {
	"key":  "00112233445566778899aabbccddeeff",
	"iv":   "00000000000000000000000000000000",
	"cmac": "aabbccddeeff00112233445566778899",
	"hmac": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
}
```

- `key` — required. 32 / 48 / 64 hex chars = 16 / 24 / 32 bytes, selects
  Camellia-128 / 192 / 256. Any other length → `create_instance` returns
  NULL.
- `iv` — optional. 32 hex chars = 16 bytes. Defaults to all zeros.
- `cmac` — optional. Must be the same hex length as `key` (the CMAC key
  length equals the cipher key length). When set, a 16-byte CMAC tag is
  appended to every message and verified on decrypt.
- `hmac` — optional. 64+ hex chars (32+ bytes), the HMAC-SHA256 key.
  When set, a 32-byte HMAC-SHA256 tag is appended to every message and
  verified on decrypt.

Both MACs can be enabled at the same time.

# Message layout

```
[ ciphertext (PKCS7-padded, 16-byte aligned) ]
[ CMAC-Camellia tag (16 bytes, only if cmac is set) ]
[ HMAC-SHA256 tag (32 bytes, only if hmac is set) ]
```

Both MACs are computed over the ciphertext only. `decrypt` verifies the
tags before decrypting and returns 0 (the message is dropped) on any
mismatch.

Buffer requirement for `encrypt`: the destination buffer must be at least
`_size + 16 + (16 if cmac) + (32 if hmac)` bytes.
