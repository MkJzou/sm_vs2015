#include <openssl/opensslconf.h>
extern "C" {
#include <ms/applink.c>
}
#include "crypto/include/internal/cryptlib.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include "openssl/x509v3.h"
#include "openssl/pem.h"
#include "openssl/pkcs12.h"
#include <openssl/sm2.h>
#include <openssl/sm3.h>
#include <openssl/sha.h>

#include "crypto/include/internal/x509_int.h"
#include "crypto/include/internal/evp_int.h"
#include "crypto/ec/ec_lcl.h"
#include "crypto/rsa/rsa_locl.h"
#include "crypto/evp/evp_locl.h"

#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <fstream>
#include <vector>
#include "char_convert.h"

void sysprintf(const char* format, ...)
{
	char acOut[512];
	va_list ap;
	va_start(ap, format);
	int n = vsprintf(acOut, format, ap);
	OutputDebugStringA(acOut);
}

// Sm2 中指定的参数  确定下 y2 = x3 + ax + b 曲线
#define _P  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"

#define _a  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"

#define _b  "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"

#define _n  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"

#define _Gx "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"

#define _Gy "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"

//extern int sm2_gen_key(PSM2_KEY sm2key)

int main(int argc, char** argv)
{
	int iFuncRet = 0;

	X509* m_pX509 = NULL;
	char acTemp[256] = { 0 };
	char acBase64[2048] = { 0 };
	unsigned char aucHex[2048] = { 0 };
	unsigned char* decode_str = aucHex;
	int iOffset = 0;
	int iRet;
	int iLen;
	bool bIsHex;
	FILE* fp = NULL;
	EVP_PKEY *pk = NULL;
	std::ofstream out;
	std::vector<char> vec;

	fp = fopen("E:\\Project\\Tools\\test\\银联动态二维码设备密钥及商户信息下载\\QR60s\\certificateExport\\Debug\\Cert\\sm2-WHTY-2018-04-04\\QRC010001320583.cer", "rb");
	if (fp == NULL)
	{
		sysprintf("文件 test.crt 打开失败");
		iFuncRet = 1;
		goto ERR_get;
	}

	fread(acTemp, 5, 1, fp);
	if (memcmp(acTemp, "-----", 5) == 0)
	{
		bIsHex = false;
	}

	if (!bIsHex)
	{
		fseek(fp, 0, SEEK_SET);
		while (feof(fp) == 0)
		{
			fgets(acTemp, sizeof(acTemp), fp);
			if (memcmp(acTemp, "-----", 5) == 0)
			{
				continue;
			}


			if (memcmp(acTemp + strlen(acTemp) - 2, "\r\n", 2) == 0)
			{
				iLen = strlen(acTemp) - 2;
			}
			else
			{
				iLen = strlen(acTemp);
			}
			memcpy(acBase64 + iOffset, acTemp, iLen);
			iOffset += iLen;
		}
		fclose(fp);

		int encode_str_size = iOffset;
		EVP_ENCODE_CTX ctx;
		EVP_DecodeInit(&ctx);
		int decode_str_size = 0;
		int len = 50;
		int decode_len = 0;
		int offset = 0;

		int ret;
		while (1)
		{
			if (offset + len > encode_str_size)
			{
				len = encode_str_size - offset;
			}

			ret = EVP_DecodeUpdate(&ctx, decode_str + decode_str_size, &decode_len,
				(unsigned char*)acBase64 + offset, len);
			if (ret == 0) break;
			if (ret == -1)
			{
				printf("error...\n");
				break;
			}
			offset += len;
			decode_str_size += decode_len;
		}
		if (ret == 0)
		{
			decode_str_size += decode_len;
		}
		EVP_DecodeFinal(&ctx, decode_str, &decode_len);
		decode_str_size += decode_len;

		m_pX509 = d2i_X509(NULL, (unsigned char const **)&decode_str, decode_str_size);
		if (m_pX509 == NULL)
		{
			sysprintf("解码失败");
			iFuncRet = 2;
			goto ERR_get;
		}
	}
	else
	{
		fseek(fp, 0, SEEK_END);
		int iLen = ftell(fp);
		fseek(fp, 0, SEEK_SET);

		fread(aucHex, iLen, 1, fp);

		m_pX509 = d2i_X509(NULL, (unsigned char const **)&decode_str, iLen);
		if (m_pX509 == NULL)
		{
			sysprintf("解码失败");
			iFuncRet = 2;
			goto ERR_get;
		}
	}

	pk = X509_get_pubkey(m_pX509);
	if (pk == NULL)
	{
		sysprintf("获取秘钥失败");
		iFuncRet = 3;
		goto ERR_get;
	}

	if (EVP_PKEY_RSA == pk->type)
	{
		sysprintf("读取公钥(RSA):\n");
		rsa_st* pub_key = pk->pkey.rsa;
		unsigned char pkN[512] = { 0 };
		unsigned char pkE[256] = { 0 };

		if (!(iRet = BN_bn2bin(pub_key->n, pkN))) { iFuncRet = 11; goto ERR_rsa; }
		int iN = BN_num_bytes(pub_key->n);
		if (!(iRet = BN_bn2bin(pub_key->e, pkE))) { iFuncRet = 11; goto ERR_rsa; }
		int iE = BN_num_bytes(pub_key->e);


	}
	else if (EVP_PKEY_EC == pk->type)
	{
		sysprintf("读取公钥(ECC)(仅限sm2p256v1):\n");
		ec_key_st* pub_key = pk->pkey.ec;
		BIGNUM *gx = NULL, *gy = NULL;
		const EC_POINT* point_q = NULL;
		EC_GROUP* group = NULL;
		unsigned char pkx[128] = { 0 };
		unsigned char pky[128] = { 0 };
		int iRet;

		if (!(gx = BN_new())) { iFuncRet = 21; goto ERR_ecc; }
		if (!(gy = BN_new())) { iFuncRet = 22; goto ERR_ecc; }
		if (!(group = EC_GROUP_new_by_curve_name(NID_sm2p256v1))) { iFuncRet = 23; goto ERR_ecc; }

		if (!(point_q = EC_KEY_get0_public_key(pub_key))) { iFuncRet = 24; goto ERR_ecc; }
		if (!EC_POINT_get_affine_coordinates_GFp(group, point_q, gx, gy, NULL)) { iFuncRet = 25; goto ERR_ecc; }

		if (!(iRet = BN_bn2bin(gx, pkx))) { iFuncRet = 26; goto ERR_ecc; }
		if (!(iRet = BN_bn2bin(gy, pky))) { iFuncRet = 27; goto ERR_ecc; }

		sysprintf("%s\n", BN_bn2hex(gx));
		sysprintf("%s\n", BN_bn2hex(gy));

	ERR_ecc:
		if (gx != NULL) BN_free(gx);
		if (gy != NULL) BN_free(gy);
		if (group != NULL) EC_GROUP_free(group);
	}
	else if (EVP_PKEY_DSA == pk->type)
	{
		sysprintf("暂不支持提取DSA秘钥");
		iFuncRet = -1;
		goto ERR_get;
		//dsa_st* pub_key = pk->pkey.dsa; 
	}
	else if (EVP_PKEY_DH == pk->type)
	{
		sysprintf("暂不支持提取DH秘钥");
		iFuncRet = -1;
		goto ERR_get;
		//dh_st* pub_key = pk->pkey.dh;
	}
	else
	{
		sysprintf("无法识别加密类型");
		iFuncRet = 4;
		goto ERR_get;
	}

	unsigned char * p = m_pX509->cert_info.enc.enc;
	vec.resize(m_pX509->cert_info.enc.len * 2 + 2);
	out.open("./waitSig_hex.txt");
	Bcd2Asc(p, &vec[0], m_pX509->cert_info.enc.len);
	out.write(&vec[0], vec.size() - 2);
	out.close();
	out.open("./waitSig.txt", std::ios_base::binary);
	out.write((char *)p, m_pX509->cert_info.enc.len);
	out.close();
	const ASN1_INTEGER *asn_id = X509_get_serialNumber(m_pX509);
	BIGNUM *bn_id = ASN1_INTEGER_to_BN(asn_id, NULL);
	sysprintf("id = %s\n", BN_bn2dec(bn_id));

	const ASN1_BIT_STRING *pig = NULL;
	const X509_ALGOR *palg = NULL;
	X509_get0_signature(&pig, &palg, m_pX509);
	const unsigned char * pdata = pig->data;
	ECDSA_SIG *s = ECDSA_SIG_new();
	d2i_ECDSA_SIG(&s, &pdata, pig->length);
	sysprintf("r = %s\n", BN_bn2hex(s->r));
	sysprintf("s = %s\n", BN_bn2hex(s->s));
	char oid[128] = { 0 };
	OBJ_obj2txt(oid, sizeof(oid), palg->algorithm, 1);
	
	sysprintf("签名算法：%s\n", oid);
	
	unsigned char sm3Hash[34];
	SHA256(m_pX509->cert_info.enc.enc, m_pX509->cert_info.enc.len, sm3Hash);
	//Asc2Bcd("5EBFAF4B0E5A1F29A44A0F2090020565836B0F7BA145C3DD4DE2F27C18935D8D", sm3Hash, 64);
	sysprintf("sm3Hash : ");
	for (int i = 0; i < 32; i++)
		sysprintf("%02x", sm3Hash[i]);
	sysprintf("\n");

	//a758dde318295a925d898952f073a3cca7acefe8c357a2d0659339ee98f15615
	sysprintf("verify : %d\n", SM2_verify/*ECDSA_verify*/(0, sm3Hash, 32, pig->data, pig->length, pk->pkey.ec));

ERR_rsa:
ERR_get:
	if (pk != NULL) EVP_PKEY_free(pk);
	if (m_pX509 != NULL) X509_free(m_pX509);

	return iFuncRet;
}