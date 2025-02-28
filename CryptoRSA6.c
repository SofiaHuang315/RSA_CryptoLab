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
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *s = BN_new();
    BIGNUM *message = BN_new();

    // Certificate4.pem Modulus
    BN_hex2bn(&n, "B8481762F7D4375F3908B5E218C87B96088C6816493868136D14126B8F1F02A319821D1333CA84F50D79FB38FF12F1194BC184867169"
                  "7E9B9638713D7884D693AB673DC774BC3B077BE1C32A9A364BB615175F23EC3FA87E8DA03436B84F8FC2E11B187E06CBF77572F4B724"
                  "874B216A557A666F6DB85C43967CF7A5B8996DA49A27C65001E1E09B6E648191FA8B8F777CE5292078F3608855272F290B7E3960357"
                  "E19F7B79CC806857E5998D6D75A88745B66A6C652C489132958D867D72A7E1789A42B6D5D7412BAA9350344413E2083044A16BF33A34");

    // Certificate4.pem Exponent
    BN_hex2bn(&e, "10001");

    // Signature from certificate4.pem
    BN_hex2bn(&s, "8b257bed81d97b7eb11ce23e8a364d7641f347b70c29ee37c7251657c25e15ade8101bda846c6278"
                  "4231e6add4e87f6b914477ac6c7b52f11519c53a8ad2cb5fcf15f3456ce881387f319a63bbadb629a9670f9eb2d97b8f10eb9284212c"
                  "5da20524b68349d9d22e74c2c6e02c27a2626e66cb726438f616a8d7d3ea7a58e4220eb7113eae8cdb8243fa61e174c6c4232068d83c"
                  "4889c863b09b75a59e960c785b82a263e4b47bcd92e30c5f13e0f88a0a39b6fcacb47741cb4186d9db");

    BN_mod_exp(message, s, e, n, ctx);

    printBN("Message = ", message);

    return 0;
}


/* This program performs RSA signature verification.
The modulus (n) and public exponent (e) are extracted from Certificate4.pem.
The signature (s) is also extracted from the certificate.
BN_mod_exp(message, s, e, n, ctx); computes message = s^e mod n, verifying the signature.
The result is printed using printBN(). */