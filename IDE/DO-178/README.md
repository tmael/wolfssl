# DO-178

## Overview
You can enable the wolfSSL support for DO-178 using the `--enable-do178 or #define HAVE_DO178`.

## Prerequisites
1. Download wolfSSL from GitHub [here](https://github.com/wolfSSL/wolfssl)

## Usage
You can build the wolfcrypt test with the DO-178 source code.

## Building and Running

1. Using command-line with a user settings configuration file:

```
$ cd ~/wolfssl
$ ./autogen.sh
$ ./configure --disable-shared --enable-do178 --enable-usersettings CFLAGS="-I./IDE/DO-178" && make clean; make && wolfcrypt/test/testwolfcrypt

```
This example uses the `/IDE/DO-178/user_settings.h` configuration, cleans, builds and runs the wolfcrypt application on your development target. You won't need to run `./autogen.sh` if you are using a tarball.

2. Using command-line with the default settings:

```
$ cd ~/wolfssl
$ ./autogen.sh
$ ./configure --disable-shared --enable-do178 && make clean; make && wolfcrypt/test/testwolfcrypt
```
Review the test results on the target console.

### `Output`

wolfcrypt test prints a message on the target console similar to the following output:

```
make -j5  all-am
make[1]: Entering directory '/home/tesfa/wolfssl'
  CC       wolfcrypt/src/src_libwolfssl_la-sha256_cert.lo
  CC       wolfcrypt/src/src_libwolfssl_la-aes_cert.lo
  CC       wolfcrypt/src/src_libwolfssl_la-sp_int.lo
  CC       wolfcrypt/src/src_libwolfssl_la-random.lo
  CC       wolfcrypt/src/src_libwolfssl_la-sp_c32.lo
  CC       wolfcrypt/src/src_libwolfssl_la-rsa_cert.lo
  CC       wolfcrypt/src/src_libwolfssl_la-asn_cert.lo
  CC       wolfcrypt/src/src_libwolfssl_la-misc.lo
  CC       wolfcrypt/src/src_libwolfssl_la-chacha_cert.lo
  CC       wolfcrypt/src/src_libwolfssl_la-poly1305_cert.lo
  CC       wolfcrypt/src/src_libwolfssl_la-chacha20_poly1305.lo
  CC       wolfcrypt/test/test.o
  CC       wolfcrypt/src/logging.o
  CCLD     src/libwolfssl.la
  CCLD     wolfcrypt/test/testwolfcrypt
make[1]: Leaving directory '/home/tesfa/wolfssl'
------------------------------------------------------------------------------
 wolfSSL version 4.3.0
------------------------------------------------------------------------------
SHA-256  test passed!
Chacha   test passed!
POLY1305 test passed!
ChaCha20-Poly1305 AEAD test passed!
AES      test passed!
AES192   test passed!
AES256   test passed!
AES-GCM  test passed!
RSA NOPAD test passed!
RSA      test passed!
Test complete

```

## Tested Configurations

SHA256
RSA Sign and Verify
    Signature Type: PKCS 1.5, PKCSPSS, OAEP
    Modulo: 2048, 3072
    Hash Algorithm: SHA2-256

AES-GCM and AES-CBC Decrypt and Encrypt
    IV Generation: Internal and external
    Key Length: 128, 192, 256
ChaCha20
Poly1305
ChaCha20 and Poly1305


## References

- wolfssl [latest version](https://github.com/wolfSSL/wolfssl)

For more information or questions, please email [support@wolfssl.com](mailto:support@wolfssl.com)
