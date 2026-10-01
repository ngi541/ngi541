# NGI541 Examples

These examples show the smallest practical use of the NGI541 public API.

They are intended for developers evaluating or integrating NGI541. They are
not correctness tests and do not replace the validation suite under `tests/`
and `validation/`.

## Examples

- `sha256.c` — initialize NGI541 and compute a SHA-256 digest.
- `aes_ctr.c` — encrypt and decrypt a short message with AES-128-CTR.
- `aes_gcm.c` — encrypt and authenticate a short message with AES-128-GCM,
  then decrypt and verify it.

All examples use only the public NGI541 interface:

```c
#include <ngi541/engine.h>
```

They do not include internal engine headers and do not depend on OpenSSL,
libacvp, or the NGI541 test framework.

## Engine lifecycle

Cryptographic operations require explicit initialization:

```c
ngi541_status_t status = ngi541_engine_init ();
```

NGI541 0.1.x does not currently expose a public shutdown/deinitialization
function. The examples therefore initialize the engine, execute their
operations, and terminate normally.

## Building

When example targets are enabled in the project build:

```sh
cmake -S . -B build -DNGI541_BUILD_EXAMPLES=ON
cmake --build build
```

Run:

```sh
./build/examples/ngi541_example_sha256
./build/examples/ngi541_example_aes_ctr
./build/examples/ngi541_example_aes_gcm
```

The exact target integration is defined by `examples/CMakeLists.txt`.

## Security note

The AES examples intentionally use fixed keys and IVs/nonces so their behavior
is deterministic and easy to inspect.

Do not copy those values into real applications.

Production applications are responsible for appropriate key management and for
meeting the uniqueness requirements of the selected mode, including avoiding
AES-CTR counter/IV reuse and AES-GCM nonce reuse under the same key.

## Public API

The examples demonstrate the current single-operation API:

- `ngi541_crypto_hash_compute()`
- `ngi541_crypto_cipher_encrypt()`
- `ngi541_crypto_cipher_decrypt()`
- `ngi541_crypto_aead_encrypt()`
- `ngi541_crypto_aead_decrypt()`

The public ABI is still in the NGI541 `0.x` development series and may evolve
before a future stable ABI release.
