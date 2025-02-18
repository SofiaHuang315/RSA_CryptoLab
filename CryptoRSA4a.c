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
    BIGNUM *sign = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *d = BN_new();

    BN_hex2bn(&n, "DCBFF3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACB26AA381CD7D30D");
    BN_hex2bn(&m, "49206F776520796F75204330302E");

    BN_mod_exp(sign, m, d, n, ctx);
    printBN("Signed Message = ", sign);

    return 0;
}

/* Explanation:
This program performs RSA signing.
m is the message being signed.
d is the private key.
n is the modulus.
BN_mod_exp(sign, m, d, n, ctx); computes the signature.
The result is printed using printBN(). */