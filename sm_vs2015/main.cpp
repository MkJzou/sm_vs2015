#include <openssl/opensslconf.h>
extern "C" {
#include <ms/applink.c>
}
#include "crypto/include/internal/cryptlib.h"

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sm2.h>
#include <openssl/sm3.h>
#include <openssl/objects.h>
#include <openssl/buffer.h>
#include <openssl/safestack.h>
#include <openssl/rand.h>


#include "crypto/include/internal/evp_int.h"
#include "crypto/include/internal/x509_int.h"
#include "crypto/include/internal/asn1_int.h"
#include "crypto/ec/ec_lcl.h"
#include "crypto/evp/evp_locl.h"
#include "crypto/asn1/asn1_locl.h"

#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <fstream>
#include <vector>

#ifdef _DEBUG
void sysprintf(const char* format, ...)
{
	char acOut[512];
	va_list ap;
	va_start(ap, format);
	int n = vsprintf(acOut, format, ap);
	OutputDebugStringA(acOut);
}

int OutputLog(char *pcBcd_Labal, unsigned char *pcAcs_Content, int iContentLen, unsigned short usSW = 0, FILE* fp = 0)
{
	int iFuncRet = 0;

	bool bExistFp = true;
	if (fp == NULL)
	{
		bExistFp = false;
		fp = fopen("./Log.txt", "ab");
		if (fp == NULL)
		{
			return -1;
		}
	}

	if (pcBcd_Labal != NULL)
	{
		iFuncRet = fputs(pcBcd_Labal, fp);
	}

	for (int i = 0; i < iContentLen; i++)
	{
		iFuncRet += fprintf(fp, "%02x", pcAcs_Content[i]);
	}
	fputc(' ', fp);

	if (usSW != 0)
	{
		fprintf(fp, "%4x", usSW);
	}
	fputc('\n', fp);


	if (!bExistFp)
	{
		fclose(fp);
	}

	return iFuncRet;
}
#endif

typedef struct {
	/* Key and paramgen group */
	EC_GROUP *gen_group;
	/* message digest */
	const EVP_MD *md;
	/* Duplicate key if custom cofactor needed */
	EC_KEY *co_key;
	/* Cofactor mode */
	signed char cofactor_mode;
	/* KDF (if any) to use for ECDH */
	char kdf_type;
	/* Message digest to use for key derivation */
	const EVP_MD *kdf_md;
	/* User key material */
	unsigned char *kdf_ukm;
	size_t kdf_ukmlen;
	/* KDF output length */
	size_t kdf_outlen;
#ifndef OPENSSL_NO_SM2
	int ec_scheme;
	char *signer_id;
	unsigned char *signer_zid;
	int ec_encrypt_param;
#endif
} EC_PKEY_CTX;

//-----------------------------------------------------------------------------------------------------

ECDSA_SIG *my_ECDSA_do_sign_ex(const unsigned char *dgst, int dlen,
	const BIGNUM *kinv, const BIGNUM *rp,
	EC_KEY *eckey)
{
	sysprintf("dgst: ");
	for (int i = 0; i < dlen; i++)
		sysprintf("%02x", dgst[i]);
	sysprintf("\n");

	if (eckey->meth->sign_sig != NULL)
		//return SM2_do_sign_ex(dgst, dlen, kinv, rp, eckey);
		return ECDSA_do_sign_ex(dgst, dlen, kinv, rp, eckey);
		//return eckey->meth->sign_sig(dgst, dlen, kinv, rp, eckey);

	ECerr(EC_F_ECDSA_DO_SIGN_EX, EC_R_OPERATION_NOT_SUPPORTED);
	return NULL;
}

int my_ECDSA_sign_ex(int type, const unsigned char *dgst, int dlen, unsigned char
	*sig, unsigned int *siglen, const BIGNUM *kinv,
	const BIGNUM *r, EC_KEY *eckey)
{
	ECDSA_SIG *s;
	RAND_seed(dgst, dlen);
	s = my_ECDSA_do_sign_ex(dgst, dlen, kinv, r, eckey);
	if (s == NULL) {
		*siglen = 0;
		return 0;
	}
	*siglen = i2d_ECDSA_SIG(s, &sig);
	ECDSA_SIG_free(s);
	return 1;
}

int my_ECDSA_sign(int type, const unsigned char *dgst, int dlen, unsigned char
	*sig, unsigned int *siglen, EC_KEY *eckey)
{
	return my_ECDSA_sign_ex(type, dgst, dlen, sig, siglen, NULL, NULL, eckey);
}

static int my_pkey_ec_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen)
{
	int ret, type;
	unsigned int sltmp;
	EC_PKEY_CTX *dctx = (EC_PKEY_CTX *)ctx->data;
	EC_KEY *ec = ctx->pkey->pkey.ec;

	if (!sig) {
		*siglen = ECDSA_size(ec);
		return 1;
	}
	else if (*siglen < (size_t)ECDSA_size(ec)) {
		ECerr(EC_F_PKEY_EC_SIGN, EC_R_BUFFER_TOO_SMALL);
		return 0;
	}

	if (dctx->md)
		type = EVP_MD_type(dctx->md);
	else
		type = NID_sha1;

	ret = my_ECDSA_sign(type, tbs, tbslen, sig, &sltmp, ec);

	if (ret <= 0)
		return ret;
	*siglen = (size_t)sltmp;
	return 1;
}

int my_EVP_PKEY_sign(EVP_PKEY_CTX *ctx,
	unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbslen)
{
	if (!ctx || !ctx->pmeth || !ctx->pmeth->sign) {
		EVPerr(EVP_F_EVP_PKEY_SIGN,
			EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
		return -2;
	}
	if (ctx->operation != EVP_PKEY_OP_SIGN) {
		EVPerr(EVP_F_EVP_PKEY_SIGN, EVP_R_OPERATON_NOT_INITIALIZED);
		return -1;
	}
	if (ctx->pmeth->flags & EVP_PKEY_FLAG_AUTOARGLEN) {
		size_t pksize = (size_t)EVP_PKEY_size(ctx->pkey);

		if (pksize == 0) {
			EVPerr(EVP_F_EVP_PKEY_SIGN, EVP_R_INVALID_KEY); /*ckerr_ignore*/
			return 0;
		}
		if (!sig) {
			*siglen = pksize;
			return 1;
		}
		if (*siglen < pksize) {
			EVPerr(EVP_F_EVP_PKEY_SIGN, EVP_R_BUFFER_TOO_SMALL); /*ckerr_ignore*/
			return 0;
		}
	}

	return ctx->pmeth->sign(ctx, sig, siglen, tbs, tbslen);
	//return my_pkey_ec_sign(ctx, sig, siglen, tbs, tbslen);
}

int my_EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sigret,
	size_t *siglen)
{
	int sctx = 0, r = 0;
	EVP_PKEY_CTX *pctx = ctx->pctx;
	if (pctx->pmeth->flags & EVP_PKEY_FLAG_SIGCTX_CUSTOM) {
		if (!sigret)
			return pctx->pmeth->signctx(pctx, sigret, siglen, ctx);
		if (ctx->flags & EVP_MD_CTX_FLAG_FINALISE)
			r = pctx->pmeth->signctx(pctx, sigret, siglen, ctx);
		else {
			EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_dup(ctx->pctx);
			if (!dctx)
				return 0;
			r = dctx->pmeth->signctx(dctx, sigret, siglen, ctx);
			EVP_PKEY_CTX_free(dctx);
		}
		return r;
	}
	if (pctx->pmeth->signctx)
		sctx = 1;
	else
		sctx = 0;
	if (sigret) {
		unsigned char md[EVP_MAX_MD_SIZE];
		unsigned int mdlen = 0;
		if (ctx->flags & EVP_MD_CTX_FLAG_FINALISE) {
			if (sctx)
				r = ctx->pctx->pmeth->signctx(ctx->pctx, sigret, siglen, ctx);
			else
				r = EVP_DigestFinal_ex(ctx, md, &mdlen);
		}
		else {
			EVP_MD_CTX *tmp_ctx = EVP_MD_CTX_new();
			if (tmp_ctx == NULL || !EVP_MD_CTX_copy_ex(tmp_ctx, ctx))
				return 0;
			if (sctx)
				r = tmp_ctx->pctx->pmeth->signctx(tmp_ctx->pctx,
					sigret, siglen, tmp_ctx);
			else
				r = EVP_DigestFinal_ex(tmp_ctx, md, &mdlen);
			EVP_MD_CTX_free(tmp_ctx);
		}

		sysprintf("hash: ");
		for (int i = 0; i < mdlen; i++) {
			sysprintf("%02x", md[i]);
		}
		sysprintf("\n");

		if (sctx || !r)
			return r;
		if (my_EVP_PKEY_sign(ctx->pctx, sigret, siglen, md, mdlen) <= 0)
			return 0;

		sysprintf("sig: ");
		for (int i = 0; i < *siglen; i++) {
			sysprintf("%02x", sigret[i]);
		}
		sysprintf("\n");
	}
	else {
		if (sctx) {
			if (pctx->pmeth->signctx(pctx, sigret, siglen, ctx) <= 0)
				return 0;
		}
		else {
			int s = EVP_MD_size(ctx->digest);
			if (s < 0 || EVP_PKEY_sign(pctx, sigret, siglen, NULL, s) <= 0)
				return 0;
		}
	}
	return 1;
}

int my_EVP_DigestSignUpdate(EVP_MD_CTX *ctx, const void *data, size_t count)
{
#ifndef OPENSSL_NO_SM2
	if (ctx->pctx && !EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_UPDATED)) {
		const unsigned char *zid;
		if (1 == EVP_PKEY_CTX_get_signer_zid(ctx->pctx, &zid)) {
			ctx->update(ctx, zid, 32);
		}
		EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_UPDATED);
	}
#endif
	return ctx->update(ctx, data, count);
}

int my_ASN1_item_sign_ctx(const ASN1_ITEM *it,
	X509_ALGOR *algor1, X509_ALGOR *algor2,
	ASN1_BIT_STRING *signature, void *asn, EVP_MD_CTX *ctx)
{
	const EVP_MD *type;
	EVP_PKEY *pkey;
	unsigned char *buf_in = NULL, *buf_out = NULL;
	size_t inl = 0, outl = 0, outll = 0;
	int signid, paramtype;
	int rv;

	type = EVP_MD_CTX_md(ctx);
	pkey = EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_pkey_ctx(ctx));

	if (type == NULL || pkey == NULL) {
		ASN1err(ASN1_F_ASN1_ITEM_SIGN_CTX, ASN1_R_CONTEXT_NOT_INITIALISED);
		goto err;
	}

	if (pkey->ameth == NULL) {
		ASN1err(ASN1_F_ASN1_ITEM_SIGN_CTX, ASN1_R_DIGEST_AND_KEY_TYPE_NOT_SUPPORTED);
		goto err;
	}

	if (pkey->ameth->item_sign) {
		rv = pkey->ameth->item_sign(ctx, it, asn, algor1, algor2, signature);
		if (rv == 1)
			outl = signature->length;
		/*-
		* Return value meanings:
		* <=0: error.
		*   1: method does everything.
		*   2: carry on as normal.
		*   3: ASN1 method sets algorithm identifiers: just sign.
		*/
		if (rv <= 0)
			ASN1err(ASN1_F_ASN1_ITEM_SIGN_CTX, ERR_R_EVP_LIB);
		if (rv <= 1)
			goto err;
	}
	else
		rv = 2;

	if (rv == 2) {
		if (!OBJ_find_sigid_by_algs(&signid,
			EVP_MD_nid(type),
			pkey->ameth->pkey_id)) {
			ASN1err(ASN1_F_ASN1_ITEM_SIGN_CTX,
				ASN1_R_DIGEST_AND_KEY_TYPE_NOT_SUPPORTED);
			goto err;
		}

		if (pkey->ameth->pkey_flags & ASN1_PKEY_SIGPARAM_NULL)
			paramtype = V_ASN1_NULL;
		else
			paramtype = V_ASN1_UNDEF;

		if (algor1)
			X509_ALGOR_set0(algor1, OBJ_nid2obj(signid), paramtype, NULL);
		if (algor2)
			X509_ALGOR_set0(algor2, OBJ_nid2obj(signid), paramtype, NULL);

	}

	inl = ASN1_item_i2d((ASN1_VALUE *)asn, &buf_in, it);
	outll = outl = EVP_PKEY_size(pkey);
	buf_out = (unsigned char *)OPENSSL_malloc((unsigned int)outl);
	if ((buf_in == NULL) || (buf_out == NULL)) {
		outl = 0;
		ASN1err(ASN1_F_ASN1_ITEM_SIGN_CTX, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	OutputLog("", buf_in, inl);

	if (!my_EVP_DigestSignUpdate(ctx, buf_in, inl)
		|| !my_EVP_DigestSignFinal(ctx, buf_out, &outl)) {
		outl = 0;
		ASN1err(ASN1_F_ASN1_ITEM_SIGN_CTX, ERR_R_EVP_LIB);
		goto err;
	}
	OPENSSL_free(signature->data);
	signature->data = buf_out;
	buf_out = NULL;
	signature->length = outl;
	/*
	* In the interests of compatibility, I'll make sure that the bit string
	* has a 'not-used bits' value of 0
	*/
	signature->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
	signature->flags |= ASN1_STRING_FLAG_BITS_LEFT;
err:
	OPENSSL_clear_free((char *)buf_in, (unsigned int)inl);
	OPENSSL_clear_free((char *)buf_out, outll);
	return (outl);
}

int my_ASN1_item_sign(const ASN1_ITEM *it, X509_ALGOR *algor1,
	X509_ALGOR *algor2, ASN1_BIT_STRING *signature, void *asn,
	EVP_PKEY *pkey, const EVP_MD *type)
{
	int rv;
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();

	if (ctx == NULL) {
		ASN1err(ASN1_F_ASN1_ITEM_SIGN, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	if (!EVP_DigestSignInit(ctx, NULL, type, NULL, pkey)) {
		EVP_MD_CTX_free(ctx);
		return 0;
	}

	rv = my_ASN1_item_sign_ctx(it, algor1, algor2, signature, asn, ctx);

	EVP_MD_CTX_free(ctx);
	return rv;
}

int my_X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md)
{
	x->cert_info.enc.modified = 1;
	return (my_ASN1_item_sign(ASN1_ITEM_rptr(X509_CINF), &x->cert_info.signature,
		&x->sig_alg, &x->signature, &x->cert_info, pkey,
		md));
}

int my_X509_REQ_sign(X509_REQ *x, EVP_PKEY *pkey, const EVP_MD *md)
{
	return (my_ASN1_item_sign(ASN1_ITEM_rptr(X509_REQ_INFO), &x->sig_alg, NULL,
		x->signature, &x->req_info, pkey, md));
}

struct st_keyvalue
{
	char* key;
	char* value;
};

// Sm2 中指定的参数  确定下 y2 = x3 + ax + b 曲线
#define _P  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"

#define _a  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"

#define _b  "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"

#define _n  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"

#define _Gx "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"

#define _Gy "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"

st_keyvalue entries[] =
{
	//{ "countryName", "CN" },
	{ "stateOrProvinceName","HB" },
	//{ "localityName", "WuHan" },
	//{ "organizationName", "WHTY" },
	{ "organizationalUnitName", "SM2" },
	{ "commonName", "WHTY" },
};

int main(int argc, char** argv)
{
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	int ret = 0;

	const char acPubX[] = "C9285CD0AC8EE148AC78D92213ECE91BA3A79752877A2177F9B0100AB45DB417";
	const char acPubY[] = "2BD34257D3CE6119964C84A9143A4278990F23DAA075F15E6B13D5E4F2B2C56A";
	const char acPri[] = "E4998D28F7F55CB7865E861552504B66F2DD933B7679951DC4AFA309A27489DB";

	BIGNUM *gx = NULL, *gy = NULL;
	BIGNUM *prv = NULL;
	EC_GROUP *group = NULL;
	EC_KEY *eckey;
	char* pszGx = NULL;
	char* pszGy = NULL;
	char* pszPrv = NULL;
	if (!(eckey = EC_KEY_new_by_curve_name(NID_sm2p256v1))) { ret = 5; goto ERR_1; }
	if (!(gx = BN_new())) { ret = 1; goto ERR_1; }
	if (!(gy = BN_new())) { ret = 2; goto ERR_1; }
	if (!(prv = BN_new())) { ret = 3; goto ERR_1; }

	if (!(group = EC_GROUP_new_by_curve_name(NID_sm2p256v1))) { ret = 4; goto ERR_1; }
	if (!BN_hex2bn(&gx, acPubX)) { ret = 5; goto ERR_1; }
	if (!BN_hex2bn(&gy, acPubY)) { ret = 6; goto ERR_1; }
	if (!BN_hex2bn(&prv, acPri)) { ret = 7; goto ERR_1; }

	pszGx = BN_bn2hex(gx);
	pszGy = BN_bn2hex(gy);
	pszPrv = BN_bn2hex(prv);
	sysprintf("%s\n", pszGx);
	sysprintf("%s\n", pszGy);
	sysprintf("%s\n", pszPrv);

	if (!EC_KEY_set_group(eckey, group)) { ret = 8; goto ERR_1; }
	if (!EC_KEY_set_private_key(eckey, prv)) { ret = 9; goto ERR_1; }
	if (!EC_KEY_set_public_key_affine_coordinates(eckey, gx, gy)) { ret = 10; goto ERR_1; }

	EVP_PKEY *key = NULL;
	if (!(key = EVP_PKEY_new())) { ret = 11; goto ERR_1; }
	if (!EVP_PKEY_set1_EC_KEY(key, eckey)) { ret = 12; goto ERR_1; }

	int ENTRY_COUNT = sizeof(entries) / sizeof(entries[0]);
	X509_REQ *req;
	struct X509_name_st *x509_name;
	const EVP_MD *digest;

	if (!(req = X509_REQ_new())) { ret = 18; goto ERR_2; }
	if (!X509_REQ_set_pubkey(req, key)) { ret = 19; goto ERR_2; }
	if (!(x509_name = X509_NAME_new())) { ret = 20; goto ERR_2; }
	for (int i = 0; i < ENTRY_COUNT; i++)
	{
		int nid;
		X509_NAME_ENTRY *ent;
		if ((nid = OBJ_txt2nid(entries[i].key)) == NID_undef)
		{
			sysprintf("为%s查找NID时出错\n", entries[i].key);
			ret = 21; goto ERR_2;
		}

		if (!(ent = X509_NAME_ENTRY_create_by_NID(NULL, nid, MBSTRING_ASC, (unsigned char *)entries[i].value, -1))) { ret = 22; goto ERR_2; }

		if (!X509_NAME_add_entry(x509_name, ent, -1, 0))
		{
			X509_NAME_ENTRY_free(ent);
			ret = 23; goto ERR_2;
		}

		if (ent != NULL) X509_NAME_ENTRY_free(ent);
	}

	if (!X509_REQ_set_subject_name(req, x509_name)) { ret = 24; goto ERR_2; }
	if (!(digest = EVP_sm3())) { ret = 25; goto ERR_2; }
	if (!my_X509_REQ_sign(req, key, digest)) { ret = 26; goto ERR_2; }

	//自签请求  生成证书
	X509* cert = NULL;
	FILE *fp = NULL;
	BIGNUM* bnSeria = NULL;
	ASN1_INTEGER *asnSeria = NULL;
	if (!(cert = X509_new())) { ret = 27; goto ERR_3; }
	if (!X509_set_version(cert, 0L)) { ret = 28; goto ERR_3; }
	if (!(bnSeria = BN_new())) { ret = 29; goto ERR_3; }
	if (!BN_dec2bn(&bnSeria, "1234567890123456")) { ret = 30; goto ERR_3; }
	if (!(asnSeria = BN_to_ASN1_INTEGER(bnSeria, NULL))) { ret = 31; goto ERR_3; }
	if (!X509_set_serialNumber(cert, asnSeria)) { ret = 32; goto ERR_3; }
	if (!X509_set_subject_name(cert, x509_name)) { ret = 33; goto ERR_3; }
	if (!X509_set_issuer_name(cert, x509_name)) { ret = 34; goto ERR_3; }
	if (!X509_set_pubkey(cert, key)) { ret = 35; goto ERR_3; }
	if (!X509_gmtime_adj(X509_get_notBefore(cert), 0)) { ret = 36; goto ERR_3; }
	if (!X509_gmtime_adj(X509_get_notAfter(cert), 315360000)) { ret = 37; goto ERR_3; }
	//if (!X509_sign(cert, key, digest)) { ret = 38; goto ERR_3; }
	//if (!(digest = EVP_sha256())) { ret = 41; goto ERR_2; }
	if (!my_X509_sign(cert, key, digest)) { ret = 38; goto ERR_3; }
	//cert->sig_alg.algorithm = OBJ_txt2obj("1.2.156.10197.1.501", 1);
	if (!(fp = fopen("test.crt", "w"))) { ret = 39; goto ERR_3; }
	if (!PEM_write_X509(fp, cert)) { ret = 40; goto ERR_3; }
	
ERR_3:
	if (fp != NULL)       fclose(fp);
	if (asnSeria != NULL) ASN1_INTEGER_free(asnSeria);
	if (bnSeria != NULL)  BN_free(bnSeria);
	if (cert != NULL)     X509_free(cert);
ERR_2:
	if (x509_name != NULL) X509_NAME_free(x509_name);
	if (req != NULL)       X509_REQ_free(req);
ERR_1:
	//if (key != NULL) EVP_PKEY_free(key);
	if (eckey != NULL) EC_KEY_free(eckey);
	if (group != NULL) EC_GROUP_free(group);
	if (prv != NULL) BN_free(prv);
	if (gy != NULL) BN_free(gy);
	if (gx != NULL) BN_free(gx);
	if (pszGx != NULL) OPENSSL_free(pszGx);
	if (pszGy != NULL) OPENSSL_free(pszGy);
	if (pszPrv != NULL) OPENSSL_free(pszPrv);

	sysprintf("ret = %d\n", ret);

	return ret;
}