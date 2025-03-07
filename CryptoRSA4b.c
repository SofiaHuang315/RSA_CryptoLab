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
    
    // BN_hex2bn(&m, "49206F776520796F752024323030302E"); // $2000
    BN_hex2bn(&m, "49206F776520796F752024333030302E"); // $3000

    BN_mod_exp(sign, m, d, n, ctx);
    printBN("Signed Message = ", sign);

    return 0;
}

/* Explanation:
This code performs RSA signing using OpenSSL.
m represents the message being signed.
The comment shows that an alternative message ($2000) was previously used, but the actual active line sets m to $3000.
The RSA private exponent d is used to sign the message using modular exponentiation (BN_mod_exp).
The resulting signed message is printed. */