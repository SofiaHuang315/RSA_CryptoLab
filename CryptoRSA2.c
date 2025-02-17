#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

void printBN(char *msg, BIGNUM *a)
{
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *m = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *enc = BN_new();
    BIGNUM *dec = BN_new();

    BN_hex2bn(&m, "4120746170207365372657421");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&n, "DCBFF3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACB26AA381CD7D30D");

    BN_mod_exp(enc, m, e, n, ctx);
    printBN("Encrypted Message = ", enc);

    BN_mod_exp(dec, enc, d, n, ctx);
    printBN("Decrypted Message = ", dec);

    return 0;
}

/* Explanation:
This program encrypts and decrypts a message using RSA.
m is the plaintext message.
e is the public exponent.
n is the RSA modulus.
d is the private key.
BN_mod_exp(enc, m, e, n, ctx); performs encryption.
BN_mod_exp(dec, enc, d, n, ctx); performs decryption.
The results are printed using printBN(). */