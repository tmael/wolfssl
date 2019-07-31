
#include <stdio.h>
#include <stdlib.h>
#include <openssl/pem.h>

#include <openssl/ssl.h>

#define CERT_FILE "/home/tesfa/wolfssl/certs/server-cert.der"


int main(int argc, char* argv[])
{
    PKCS7* pkcs7;
    X509* x509;
    //STACK_OF(X509)* x509=NULL;
    FILE* f;
    BIO* bio;

    PKCS7 *p7 = NULL;
    PKCS7_SIGNED   *p7s = NULL;
    BIO *bioPkcs = NULL;
    BUF_MEM * bioPkcsData = NULL;
    BUF_MEM * bioPkcsData2 = NULL;

    if (argc < 2) {
        printf("usage: %s <path to a der x509>\n", argv[0]);
        printf("For now, using default file %s \n", CERT_FILE);
        f = fopen(CERT_FILE, "rb");
    }
    else {
    	f = fopen(argv[1], "rb");
    }

    if (f == NULL) {
        printf("unable to read file %s\n", argv[1]);
        return 1;
    }

    x509 = d2i_X509_fp(f, NULL);

    fclose(f);

    if (x509 == NULL) {
        printf("unable to parse x509\n");
        return 1;
    }

    printf("****Method #1**************************************************\n");
    p7 = PKCS7_new();
    p7s = PKCS7_SIGNED_new();
    p7->type = OBJ_nid2obj(NID_pkcs7_signed);
    p7->d.sign = p7s;
    p7s->contents->type = OBJ_nid2obj(NID_pkcs7_data);
    p7s->cert = (STACK_OF(X509)*)x509;

    bioPkcs = BIO_new(BIO_s_mem());

    PEM_write_bio_PKCS7(bioPkcs, p7);
    BIO_get_mem_ptr(bioPkcs, &bioPkcsData);

    printf("Actual Data = %s\n", bioPkcsData->data);
    printf("Actual length of PKCS7 buffer = %ld\n\n", bioPkcsData->length);

    printf("****Method #2**************************************************\n");
    pkcs7 = PKCS7_new();

    printf("ret of PKCS7_set_type = %d\n", PKCS7_set_type(pkcs7, NID_pkcs7_signed));

    printf("ret of PKCS7_content_new = %d\n", PKCS7_content_new(pkcs7, NID_pkcs7_data));

    printf("ret of add cert PKCS7_add_certificate = %d\n", PKCS7_add_certificate(pkcs7, x509));

    bio = BIO_new(BIO_s_file());
    BIO_set_fp(bio, stdout, BIO_NOCLOSE);
    printf("pkcs7 : \n");
    PEM_write_bio_PKCS7(bio, pkcs7);
    printf("\n");

    BIO_get_mem_ptr(bio, &bioPkcsData2);

    printf("Actual Data = %s\n", bioPkcsData2->data);
    printf("Actual length of PKCS7 buffer = %ld\n\n", bioPkcsData2->length);


    BIO_free(bioPkcs);
    PKCS7_free(p7);

    BIO_free(bio);
    PKCS7_free(pkcs7);
    return 0;
}

/*
$ gcc -g mehednra_hp_pkcs7_signed.c -o mehednra_hp_pkcs7_signed.out -L/opt/openssl/lib -I/opt/openssl/include -lssl -lcrypto
$ ./mehednra_hp_pkcs7_signed.out
usage: ./mehednra_hp_pkcs7_signed.out <path to a der x509>
For now, using default file /home/tesfa/wolfssl/certs/server-cert.der
****Method #1**************************************************
Actual Data = -----BEGIN PKCS7-----
MCUGCSqGSIb3DQEHAqAYMBYCAQAxADALBgkqhkiG9w0BBwGgADEA
-----END PKCS7-----
152310Z0�q
Actual length of PKCS7 buffer = 95

****Method #2**************************************************
ret of PKCS7_set_type = 1
ret of PKCS7_content_new = 1
ret of add cert PKCS7_add_certificate = 1
pkcs7 :
-----BEGIN PKCS7-----
MIIE0QYJKoZIhvcNAQcCoIIEwjCCBL4CAQExADAPBgkqhkiG9w0BBwGgAgQAoIIE
ojCCBJ4wggOGoAMCAQICAQEwDQYJKoZIhvcNAQELBQAwgZQxCzAJBgNVBAYTAlVT
MRAwDgYDVQQIDAdNb250YW5hMRAwDgYDVQQHDAdCb3plbWFuMREwDwYDVQQKDAhT
YXd0b290aDETMBEGA1UECwwKQ29uc3VsdGluZzEYMBYGA1UEAwwPd3d3LndvbGZz
c2wuY29tMR8wHQYJKoZIhvcNAQkBFhBpbmZvQHdvbGZzc2wuY29tMB4XDTE4MDQx
MzE1MjMxMFoXDTIxMDEwNzE1MjMxMFowgZAxCzAJBgNVBAYTAlVTMRAwDgYDVQQI
DAdNb250YW5hMRAwDgYDVQQHDAdCb3plbWFuMRAwDgYDVQQKDAd3b2xmU1NMMRAw
DgYDVQQLDAdTdXBwb3J0MRgwFgYDVQQDDA93d3cud29sZnNzbC5jb20xHzAdBgkq
hkiG9w0BCQEWEGluZm9Ad29sZnNzbC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDAlQjhV0HycW230kVBJwFlxkWu8rwkMLiVzi9O1vYciLx8n/uo
Z3/+XJxRdfeKygfnNS+P4b17wC98q2SoF/zKXXu64CHlci5vLobYlXParBtTuV8/
1xkNJU/hY2NRiwtkP61DuKUcXDSzrgCgY8X2fwtZaHhzpowYqQJtr8MZAS64EOPG
zEC0aaNGM2mHbsS7F6bz6N2tc7x7LyG1/WZRDL1Us+FtXxy8I3PRCQOJFNIQuWTD
KtChlkq84dQaW8egwMFjeA9ENzAyloAyI5Whd7oT0pdz4l0lyWoNwzlgpLSwaUJC
CenYCLwzILNYIqeq68Th5mGDxdKW39nQT63XAgMBAAGjgfwwgfkwHQYDVR0OBBYE
FLMRMsmSmITiyfjQO24DQsofDo48MIHJBgNVHSMEgcEwgb6AFCeOZxF0wyYdP+0z
Y7Ok2B0w5ejVoYGapIGXMIGUMQswCQYDVQQGEwJVUzEQMA4GA1UECAwHTW9udGFu
YTEQMA4GA1UEBwwHQm96ZW1hbjERMA8GA1UECgwIU2F3dG9vdGgxEzARBgNVBAsM
CkNvbnN1bHRpbmcxGDAWBgNVBAMMD3d3dy53b2xmc3NsLmNvbTEfMB0GCSqGSIb3
DQEJARYQaW5mb0B3b2xmc3NsLmNvbYIJAIb/9Y4Q3rj7MAwGA1UdEwQFMAMBAf8w
DQYJKoZIhvcNAQELBQADggEBALRUYK2gAzLeAn8hSoHG7c3N2BKKwLqCW3WtVON8
gGqsLmwgTr5NgqdHE1z0xmorEJlY3qtrfCIFwYOdy/885C1XaqaW39PBaOPSxoNL
l+LGMg6+xAO5B4pbuIS6xTk/HFinVdfwm+jSRbnjgy7utnFWuTruPyfYd+j7REhl
J0dM+/5yw6wFex3L615lmqsC5IhbO4sLx8yppovhh7AZGgwoWG+ZUn7tsDpoO4wK
CHRyq7kJxe0Efm8LHAkh0M1/+cReJyDkhXNSBdK6+NWPQcwjLhJtvDGY52OjjibN
6CuI7uL+OnRSNA79EuVeaVAgMTTkMfHn5FsDE9qsQWznzysxAA==
-----END PKCS7-----

Segmentation fault (core dumped)
$

*/
