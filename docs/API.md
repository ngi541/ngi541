# NGI541 Public API

This document describes the public C API exposed by the NGI541 `0.1.x`
release line.

The public API is intentionally small. It provides explicit engine
initialization and request-based execution for the currently supported
cryptographic primitives.

The authoritative public headers are installed under:

```text
include/ngi541/
├── api.h
├── crypto.h
└── engine.h
```

Applications must not include headers from `src/` or depend on internal engine
types.

For the broader production architecture, see
[`architecture.md`](architecture.md).

## 1. API model

The public execution model is:

```text
application
    |
    v
ngi541_engine_init()
    |
    v
public request structure
    |
    v
ngi541_crypto_*()
    |
    v
ngi541_status_t
```

Each cryptographic operation is represented by a public request structure.

The current API is operation-oriented: one request describes one
cryptographic operation.

Internal engine operation structures are not part of the public API or ABI.

## 2. Public headers

### `ngi541/api.h`

Defines public API visibility and declaration support used by the installed
headers.

### `ngi541/crypto.h`

Defines:

- public status codes;
- supported cipher, AEAD, and hash algorithm identifiers;
- public request structures;
- cryptographic execution functions.

### `ngi541/engine.h`

Defines the public engine lifecycle entry point:

```c
ngi541_status_t ngi541_engine_init(void);
```

`engine.h` is the normal top-level include used by the project examples.

## 3. Engine lifecycle

Cryptographic operations require successful engine initialization.

A typical application starts with:

```c
ngi541_status_t status = ngi541_engine_init();

if (status != NGI541_STATUS_OK) {
    /* handle initialization failure */
}
```

Calling a cryptographic operation before successful initialization returns:

```text
NGI541_STATUS_NOT_INITIALIZED
```

Repeated successful initialization is supported by the current public
contract. An application does not need to track whether another successful
initialization call has already occurred in the same process before calling
`ngi541_engine_init()` again.

NGI541 `0.1.x` does not expose a public shutdown or deinitialization function.

The current lifecycle is therefore:

```text
process start
    |
    v
ngi541_engine_init()
    |
    v
cryptographic operations
    |
    v
process exit
```

Applications must not call internal provider or engine initialization
functions directly.

## 4. Status model

Public functions return `ngi541_status_t`.

The currently defined statuses are:

| Status | Value | Meaning |
| --- | ---: | --- |
| `NGI541_STATUS_OK` | 0 | Operation completed successfully. |
| `NGI541_STATUS_AUTH_FAILED` | 1 | Authentication verification failed, for example during authenticated decryption. |
| `NGI541_STATUS_INVALID_ARGUMENT` | 2 | One or more request arguments are invalid. |
| `NGI541_STATUS_BUFFER_TOO_SMALL` | 3 | The provided output capacity is insufficient. |
| `NGI541_STATUS_UNSUPPORTED` | 4 | The requested algorithm or operation is not supported by the public implementation. |
| `NGI541_STATUS_UNAVAILABLE` | 5 | A required implementation path is unavailable in the current execution environment. |
| `NGI541_STATUS_NOT_INITIALIZED` | 6 | The engine has not been successfully initialized. |
| `NGI541_STATUS_INTERNAL_ERROR` | 7 | An internal execution failure occurred. |

Applications should check the returned status from every public operation.

A non-zero status must not be treated as successful completion.

## 5. Common request convention

All public request structures contain:

```c
struct_size
```

Consumers must initialize this field to the size of the request structure being
passed:

```c
.struct_size = sizeof(request)
```

The examples and validation infrastructure use this convention consistently.

Callers are responsible for:

- supplying valid input pointers for non-zero input lengths;
- supplying output storage with sufficient capacity;
- keeping referenced input data valid for the duration of the call;
- checking the returned status before consuming operation results.

NGI541 does not take ownership of caller-provided input or output buffers.

## 6. AES-CBC

AES-CBC is selected with:

```c
NGI541_CIPHER_AES_CBC
```

Supported AES key lengths are:

```text
16 bytes   AES-128
24 bytes   AES-192
32 bytes   AES-256
```

Encryption and decryption use `ngi541_cipher_request_t`.

Conceptually:

```c
ngi541_cipher_request_t request = {
    .struct_size = sizeof(request),
    .algorithm = NGI541_CIPHER_AES_CBC,
    .key = key,
    .key_len = key_len,
    .iv = iv,
    .iv_len = iv_len,
    .input = input,
    .input_len = input_len,
    .output = output,
    .output_capacity = output_capacity,
};
```

Encrypt:

```c
ngi541_status_t status =
    ngi541_crypto_cipher_encrypt(&request);
```

Decrypt:

```c
ngi541_status_t status =
    ngi541_crypto_cipher_decrypt(&request);
```

NGI541 exposes raw CBC primitive execution. Padding policy is not provided by
the public execution API and must not be assumed to be performed implicitly.

Callers must provide inputs that satisfy the selected mode's requirements.

## 7. AES-CTR

AES-CTR is selected with:

```c
NGI541_CIPHER_AES_CTR
```

Supported AES key lengths are:

```text
16 bytes   AES-128
24 bytes   AES-192
32 bytes   AES-256
```

AES-CTR uses the same `ngi541_cipher_request_t` structure as AES-CBC.

Example:

```c
ngi541_cipher_request_t request = {
    .struct_size = sizeof(request),
    .algorithm = NGI541_CIPHER_AES_CTR,
    .key = key,
    .key_len = sizeof(key),
    .iv = counter,
    .iv_len = sizeof(counter),
    .input = input,
    .input_len = input_len,
    .output = output,
    .output_capacity = output_capacity,
};
```

Encryption:

```c
ngi541_crypto_cipher_encrypt(&request);
```

Decryption:

```c
ngi541_crypto_cipher_decrypt(&request);
```

The caller is responsible for correct key and counter/IV management.

In particular, applications must not reuse the same AES-CTR counter/IV with the
same key in contexts where uniqueness is required for security.

## 8. Cipher buffer overlap

The public cipher API permits exact in-place AES-CTR operation.

That means the same buffer may be used as both input and output when the
operation is explicitly supported as exact in-place execution.

Distinct partially overlapping input and output ranges are invalid.

Conceptually:

```text
input == output
    supported where explicitly permitted

input overlaps output only partially
    invalid
```

Applications should prefer either:

- fully separate input and output buffers; or
- exact in-place operation where the public contract permits it.

Do not rely on undocumented overlap behavior.

## 9. AES-GCM

AES-GCM is selected with:

```c
NGI541_AEAD_AES_GCM
```

Supported AES key lengths are:

```text
16 bytes   AES-128
24 bytes   AES-192
32 bytes   AES-256
```

Authenticated encryption and authenticated decryption use separate public
request structures.

### Encryption

`ngi541_aead_encrypt_request_t` contains:

```text
struct_size
algorithm
key
key_len
iv
iv_len
aad
aad_len
plaintext
plaintext_len
ciphertext
ciphertext_capacity
tag
tag_len
```

Typical initialization:

```c
ngi541_aead_encrypt_request_t request = {
    .struct_size = sizeof(request),
    .algorithm = NGI541_AEAD_AES_GCM,
    .key = key,
    .key_len = key_len,
    .iv = iv,
    .iv_len = iv_len,
    .aad = aad,
    .aad_len = aad_len,
    .plaintext = plaintext,
    .plaintext_len = plaintext_len,
    .ciphertext = ciphertext,
    .ciphertext_capacity = ciphertext_capacity,
    .tag = tag,
    .tag_len = tag_len,
};
```

Execute with:

```c
ngi541_status_t status =
    ngi541_crypto_aead_encrypt(&request);
```

On success, the caller-provided ciphertext and tag buffers contain the
authenticated-encryption result.

### Decryption

`ngi541_aead_decrypt_request_t` contains the corresponding authenticated
decryption fields:

```text
struct_size
algorithm
key
key_len
iv
iv_len
aad
aad_len
ciphertext
ciphertext_len
tag
tag_len
plaintext
plaintext_capacity
```

Execute with:

```c
ngi541_status_t status =
    ngi541_crypto_aead_decrypt(&request);
```

The caller must check the returned status before treating the plaintext output
as authenticated.

## 10. Authentication failure semantics

AES-GCM decryption can return:

```text
NGI541_STATUS_AUTH_FAILED
```

This indicates that authentication verification failed.

An application must treat this as a failed operation and must not accept the
decrypted output as authenticated plaintext.

The normal control flow is:

```text
AES-GCM decrypt
      |
      +--> NGI541_STATUS_OK
      |        |
      |        v
      |   plaintext accepted
      |
      +--> NGI541_STATUS_AUTH_FAILED
               |
               v
          reject message
```

Applications must not collapse `AUTH_FAILED` into successful decryption.

## 11. SHA-224 and SHA-256

Hash operations use `ngi541_hash_request_t`.

Supported identifiers are:

```c
NGI541_HASH_SHA2_224
NGI541_HASH_SHA2_256
```

The request contains:

```text
struct_size
algorithm
message
message_len
digest
digest_capacity
```

Example:

```c
uint8_t digest[32];

ngi541_hash_request_t request = {
    .struct_size = sizeof(request),
    .algorithm = NGI541_HASH_SHA2_256,
    .message = message,
    .message_len = message_len,
    .digest = digest,
    .digest_capacity = sizeof(digest),
};
```

Execute with:

```c
ngi541_status_t status =
    ngi541_crypto_hash_compute(&request);
```

The caller must provide enough digest capacity for the selected hash
algorithm.

Current digest sizes are:

```text
SHA2-224   28 bytes
SHA2-256   32 bytes
```

## 12. Buffer ownership and lifetime

NGI541 does not allocate or retain application buffers through the current
single-operation public API.

The caller owns:

- keys;
- IVs or counters;
- AAD;
- plaintext and ciphertext buffers;
- message buffers;
- digest buffers;
- authentication tag buffers.

Referenced input data must remain valid for the duration of the function call.

Output buffers must be writable and large enough for the requested operation.

The public request structures describe caller-owned memory; they do not
transfer ownership to NGI541.

## 13. Output capacity

Output request structures separate logical input length from available output
capacity.

Examples include:

```text
output_capacity
ciphertext_capacity
plaintext_capacity
digest_capacity
```

Callers must provide sufficient capacity before invoking the operation.

If the supplied capacity is insufficient, the operation may return:

```text
NGI541_STATUS_BUFFER_TOO_SMALL
```

Applications must not assume that NGI541 dynamically grows or reallocates
caller-provided buffers.

## 14. Invalid arguments

Malformed requests may return:

```text
NGI541_STATUS_INVALID_ARGUMENT
```

Examples of invalid request classes include:

- invalid pointers for non-zero lengths;
- unsupported key lengths;
- invalid buffer relationships;
- invalid request structure metadata;
- parameters that do not satisfy the selected algorithm contract.

Applications should treat `INVALID_ARGUMENT` as a programming or input
validation failure rather than retrying the same request unchanged.

## 15. Unsupported and unavailable operations

The public API distinguishes:

```text
NGI541_STATUS_UNSUPPORTED
```

from:

```text
NGI541_STATUS_UNAVAILABLE
```

`UNSUPPORTED` indicates that the requested algorithm or operation is not part
of the supported implementation surface.

`UNAVAILABLE` indicates that an otherwise recognized implementation path cannot
be used in the current execution environment.

Applications should not assume that every build or processor necessarily
provides every internal ISA path.

Platform and ISA support are documented separately in
[`PLATFORMS.md`](PLATFORMS.md).

## 16. Thread safety

NGI541 `0.1.x` does not currently declare a public thread-safety guarantee.

The public API documentation therefore does not promise that:

- concurrent calls to `ngi541_engine_init()` are safe;
- all cryptographic operations may be invoked concurrently without external
  synchronization;
- initialization and operation calls may safely race across threads.

Consumers that require concurrent use must treat thread-safety behavior as
unspecified by the current public contract and provide appropriate external
synchronization until an explicit guarantee is documented.

A future release may strengthen this contract after the implementation and
concurrency behavior are specifically validated.

## 17. Error handling pattern

A minimal error-handling pattern is:

```c
ngi541_status_t status = ngi541_engine_init();

if (status != NGI541_STATUS_OK) {
    return 1;
}

status = ngi541_crypto_hash_compute(&request);

if (status != NGI541_STATUS_OK) {
    return 2;
}
```

Applications should preserve the distinction between status values where it is
security-relevant, especially for authenticated decryption.

## 18. CMake consumer contract

The canonical installed static target is:

```cmake
NGI541::engine
```

Example:

```cmake
find_package(
    NGI541
    CONFIG
    REQUIRED
)

add_executable(
    my_app
    main.c
)

target_link_libraries(
    my_app
    PRIVATE
        NGI541::engine
)
```

A shared target is also available:

```cmake
NGI541::engine_shared
```

The following installed CMake targets are internal implementation details and
must not be treated as public API:

```text
NGI541::_core
NGI541::_support
NGI541::_crypto_isa
```

## 19. pkg-config consumer contract

On supported Unix-like installations, NGI541 also installs:

```text
ngi541.pc
```

A consumer can obtain compiler and linker flags with:

```bash
pkg-config --cflags --libs ngi541
```

Static consumers can request private static dependencies with:

```bash
pkg-config --static --cflags --libs ngi541
```

The CMake package remains the canonical cross-platform package interface.

## 20. Security responsibilities of callers

NGI541 executes cryptographic primitives; it does not provide a complete
application security policy.

Applications remain responsible for matters including:

- cryptographically appropriate key generation;
- secure key storage and lifecycle management;
- IV, nonce, and counter uniqueness requirements;
- protocol-level replay protection;
- choosing algorithms and parameters appropriate for their protocol;
- rejecting authentication failures;
- protecting sensitive data outside the NGI541 call boundary.

The deterministic keys and IVs used by examples are demonstration values only
and must not be copied into production applications.

## 21. Public API versus validation API

ACVP and other validation tooling exercise the public NGI541 API.

There is no separate consumer-facing ACVP execution API that applications are
expected to use.

Conceptually:

```text
Application --------+
                    |
Validation tooling -+--> Public NGI541 API --> Production engine
```

Validation-specific interfaces under `validation/` are not production APIs.

See [`validation.md`](validation.md) for the validation evidence model.

## 22. ABI and version policy

NGI541 remains in the `0.x` development series.

The public API boundary is established, but long-term ABI stability is not
claimed across all `0.x` releases.

The canonical ABI policy is documented in:

```text
docs/ABI.md
```

Until that document is finalized, consumers should not infer ABI guarantees
beyond the compatibility policy published for the specific release line.

Internal headers, internal engine structures, and `NGI541::_*` CMake targets
are outside the public ABI.

## 23. Examples

Runnable public API examples are available under:

```text
examples/
├── README.md
├── sha256.c
├── aes_ctr.c
└── aes_gcm.c
```

They demonstrate:

- engine initialization;
- SHA-256 hashing;
- AES-CTR encryption/decryption round-trip;
- AES-GCM authenticated encryption/decryption round-trip;
- public status checking;
- caller-managed buffers.

The examples use only installed public headers and do not depend on OpenSSL,
libacvp, test helpers, or internal NGI541 headers.

## 24. API non-goals

The NGI541 `0.1.x` public API does not attempt to provide:

- TLS protocol handling;
- X.509 or certificate processing;
- PKI;
- key storage;
- key-management infrastructure;
- a generic EVP-style abstraction;
- public access to internal operation descriptors;
- a stable public batch API;
- validation-specific semantics as application interfaces.

A future batch-oriented API may be introduced separately after its semantics,
performance requirements, and compatibility policy are defined.

## 25. Related documentation

See also:

- [`architecture.md`](architecture.md) for the production architecture and
  public/internal boundaries;
- [`validation.md`](validation.md) for correctness and ACVP evidence;
- [`legal/PROVENANCE.md`](legal/PROVENANCE.md) for source provenance;
- `ABI.md` for release and ABI compatibility policy once finalized;
- `PLATFORMS.md` for supported operating systems, architectures, compilers,
  and ISA behavior once finalized.
