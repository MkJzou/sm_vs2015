/* ====================================================================
 * Copyright (c) 2016 - 2017 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <string.h>
#include <openssl/err.h>
#include <openssl/gmsdf.h>
#include "internal/sdf_int.h"
#include "../../e_os.h"



static void print_str(const char *name, const void *value)
{
	(void)printf("%-20s: %s\n", name, (char *)value);
}

static void print_int(const char *name, unsigned int value)
{
	(void)printf("%-20s: %u\n", name, value);
}

/*
static void print_buf(const char *name, const unsigned char *buf, size_t buflen)
{
	size_t i;
	(void)printf("%-20s: ", name);
	for (i = 0; i < buflen; i++) {
		(void)printf("%02x", buf[i]);
	}
	(void)puts("\n");
}
*/

typedef struct {
	ULONG id;
	char *name;
} table_item_t;

static table_item_t sdf_cipher_caps[] = {
	{ SGD_SM1_ECB, "sm1-ecb" },
	{ SGD_SM1_CBC, "sm1-cbc" },
	{ SGD_SM1_CFB, "sm1-cfb" },
	{ SGD_SM1_OFB, "sm1-ofb128" },
	{ SGD_SM1_MAC, "cbcmac-sm1" },
	{ SGD_SSF33_ECB, "ssf33-ecb" },
	{ SGD_SSF33_CBC, "ssf33-cbc" },
	{ SGD_SSF33_CFB, "ssf33-cfb" },
	{ SGD_SSF33_OFB, "ssf33-ofb128" },
	{ SGD_SSF33_MAC, "cbcmac-ssf33" },
	{ SGD_SM4_ECB, "sms4-ecb" },
	{ SGD_SM4_CBC, "sms4-cbc" },
	{ SGD_SM4_CFB, "sms4-cfb" },
	{ SGD_SM4_OFB, "sms4-ofb128" },
	{ SGD_SM4_MAC, "cbcmac-sms4" },
	{ SGD_ZUC_EEA3, "zuc_128eea3" },
	{ SGD_ZUC_EIA3, "zuc_128eia3" }
};

static table_item_t sdf_digest_caps[] = {
	{ SGD_SM3,  "sm3" },
	{ SGD_SHA1, "sha1" },
	{ SGD_SHA256, "sha256" },
};

static table_item_t sdf_pkey_caps[] = {
	{ SGD_RSA_SIGN, "rsa" },
	{ SGD_RSA_ENC, "rsaEncryption" },
	{ SGD_SM2_1, "sm2sign" },
	{ SGD_SM2_2, "sm2exchange" },
	{ SGD_SM2_3, "sm2encrypt" }
};

int SDF_PrintDeviceInfo(DEVICEINFO *pstDeviceInfo)
{
	int i, n;
	DEVICEINFO buf;
	DEVICEINFO *devInfo = &buf;

	memcpy(devInfo, pstDeviceInfo, sizeof(DEVICEINFO));
	devInfo->IssuerName[39] = 0;
	devInfo->DeviceName[15] = 0;
	devInfo->DeviceSerial[15] = 0;

	print_str("  Issuer", devInfo->IssuerName);
	print_str("  Device Name", devInfo->DeviceName);
	print_str("  Serial Number", devInfo->DeviceSerial);
	print_int("  Hardware Version", devInfo->DeviceVersion);
	print_int("  Standard Version", devInfo->StandardVersion);
	printf("%-20s: ", "  Public Key Algors");
	for (i = n = 0; i < OSSL_NELEM(sdf_pkey_caps); i++) {
		if ((devInfo->AsymAlgAbility[0] & sdf_pkey_caps[i].id) ==
			sdf_pkey_caps[i].id) {
			printf("%s%s", n ? ", " : "", sdf_pkey_caps[i].name);
			n++;
		}
	}
	printf("\n");

	printf("%-20s: ", "  Ciphers");
	for (i = n = 0; i < OSSL_NELEM(sdf_cipher_caps); i++) {
		if ((devInfo->SymAlgAbility & sdf_cipher_caps[i].id) ==
			sdf_cipher_caps[i].id) {
			printf("%s%s", n ? ", " : "", sdf_cipher_caps[i].name);
			n++;
		}
	}
	printf("\n");

	printf("%-20s: ", "  Digests");
	for (i = n = 0; i < OSSL_NELEM(sdf_digest_caps); i++) {
		if ((devInfo->HashAlgAbility & sdf_digest_caps[i].id) ==
			sdf_digest_caps[i].id) {
			printf("%s%s", n ? ", " : "", sdf_digest_caps[i].name);
			n++;
		}
	}
	printf("\n");


	return SDR_OK;
}

int SDF_PrintRSAPublicKey(RSArefPublicKey *blob)
{
	BIO *bio = NULL;

	if (!(bio = BIO_new_fp(stdout, BIO_NOCLOSE))) {
		return SDR_UNKNOWERR;
	}

	(void)BIO_printf(bio, "bits: %d\n", blob->bits);
	(void)BIO_printf(bio, "m:\n    ");
	(void)BIO_hex_string(bio, 4, 16, blob->m, sizeof(blob->m));
	(void)BIO_printf(bio, "\n");
	(void)BIO_printf(bio, "e:\n    ");
	(void)BIO_hex_string(bio, 4, 16, blob->e, sizeof(blob->e));
	(void)BIO_printf(bio, "\n");

	BIO_free(bio);
	return SDR_OK;
}

int SDF_PrintRSAPrivateKey(RSArefPrivateKey *blob)
{
	BIO *bio = NULL;

	if (!(bio = BIO_new_fp(stdout, BIO_NOCLOSE))) {
		return SDR_UNKNOWERR;
	}

	(void)BIO_printf(bio, "bits: %d", blob->bits);
	(void)BIO_printf(bio, "\n%s:\n    ", "m");
	(void)BIO_hex_string(bio, 4, 16, blob->m, sizeof(blob->m));
	(void)BIO_printf(bio, "\n%s:\n    ", "e");
	(void)BIO_hex_string(bio, 4, 16, blob->e, sizeof(blob->e));
	(void)BIO_printf(bio, "\n%s:\n    ", "d");
	(void)BIO_hex_string(bio, 4, 16, blob->d, sizeof(blob->d));
	(void)BIO_printf(bio, "\n%s:\n    ", "prime[0]");
	(void)BIO_hex_string(bio, 4, 16, blob->prime[0], sizeof(blob->prime[0]));
	(void)BIO_printf(bio, "\n%s:\n    ", "prime[1]");
	(void)BIO_hex_string(bio, 4, 16, blob->prime[1], sizeof(blob->prime[1]));
	(void)BIO_printf(bio, "\n%s:\n    ", "pexp[0]");
	(void)BIO_hex_string(bio, 4, 16, blob->pexp[0], sizeof(blob->pexp[0]));
	(void)BIO_printf(bio, "\n%s:\n    ", "pexp[1]");
	(void)BIO_hex_string(bio, 4, 16, blob->pexp[1], sizeof(blob->pexp[1]));
	(void)BIO_printf(bio, "\n%s:\n    ", "coef");
	(void)BIO_hex_string(bio, 4, 16, blob->coef, sizeof(blob->coef));
	(void)BIO_printf(bio, "\n");

	BIO_free(bio);
	return SDR_OK;
}

int SDF_PrintECCPublicKey(ECCrefPublicKey *blob)
{
	BIO *bio = NULL;

	if (!(bio = BIO_new_fp(stdout, BIO_NOCLOSE))) {
		return SDR_UNKNOWERR;
	}

	(void)BIO_printf(bio, "bits: %d", blob->bits);
	(void)BIO_printf(bio, "\n%s:\n    ", "x");
	(void)BIO_hex_string(bio, 4, 16, blob->x, sizeof(blob->x));
	(void)BIO_printf(bio, "\n%s:\n    ", "y");
	(void)BIO_hex_string(bio, 4, 16, blob->y, sizeof(blob->y));
	(void)BIO_printf(bio, "\n");

	BIO_free(bio);
	return SDR_OK;
}

int SDF_PrintECCPrivateKey(ECCrefPrivateKey *blob)
{
	BIO *bio = NULL;

	if (!(bio = BIO_new_fp(stdout, BIO_NOCLOSE))) {
		return SDR_UNKNOWERR;
	}

	(void)BIO_printf(bio, "bits: %d", blob->bits);
	(void)BIO_printf(bio, "\n%s:\n    ", "K");
	(void)BIO_hex_string(bio, 4, 16, blob->K, sizeof(blob->K));
	(void)BIO_printf(bio, "\n");

	BIO_free(bio);
	return SDR_OK;
}

int SDF_PrintECCCipher(ECCCipher *blob)
{
	BIO *bio = NULL;

	if (!(bio = BIO_new_fp(stdout, BIO_NOCLOSE))) {
		return SDR_UNKNOWERR;
	}

	(void)BIO_printf(bio, "%s:\n    ", "x");
	(void)BIO_hex_string(bio, 4, 16, blob->x, sizeof(blob->x));
	(void)BIO_printf(bio, "\n%s:\n    ", "y");
	(void)BIO_hex_string(bio, 4, 16, blob->y, sizeof(blob->y));
	(void)BIO_printf(bio, "\n%s:\n    ", "M");
	(void)BIO_hex_string(bio, 4, 16, blob->M, sizeof(blob->M));
	(void)BIO_printf(bio, "\nL: %d", blob->L);
	(void)BIO_printf(bio, "\n%s:\n    ", "C");
	(void)BIO_hex_string(bio, 4, 16, blob->C, sizeof(blob->C));
	(void)BIO_printf(bio, "\n");

	BIO_free(bio);
	return SDR_OK;
}

int SDF_PrintECCSignature(ECCSignature *blob)
{
	BIO *bio = NULL;

	if (!(bio = BIO_new_fp(stdout, BIO_NOCLOSE))) {
		return SDR_UNKNOWERR;
	}

	(void)BIO_printf(bio, "%s:\n    ", "r");
	(void)BIO_hex_string(bio, 4, 16, blob->r, sizeof(blob->r));
	(void)BIO_printf(bio, "\n%s:\n    ", "s");
	(void)BIO_hex_string(bio, 4, 16, blob->s, sizeof(blob->s));
	(void)BIO_printf(bio, "\n");

	BIO_free(bio);
	return SDR_OK;
}

int SDF_ImportKey(
	void *hSessionHandle,
	unsigned char *pucKey,
	unsigned int uiKeyLength,
	void **phKeyHandle)
{
	return 0;
}
