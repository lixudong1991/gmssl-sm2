#include "com_sim_diskservice_Utils_SM2Util.h"
#include <openssl/sm2.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/sm3.h>
# include <openssl/evp.h>
//static  char*  BinToHexStr(char *content, unsigned int clen, char *result, unsigned int *reslen);
static int setPubKey(const char *pubkey,EC_KEY** pkey);
static int setPriKey(const char *prikey,EC_KEY** pkey,int issetpubkey);
static int getSm2Key(char keypair[], unsigned int len)
{
	EC_KEY *eckey = NULL;
	EC_GROUP *group1 = NULL;
	if (len < 193)
		return 0;
	eckey = EC_KEY_new();
	if (!eckey) {
		return -1;
	}
	group1 = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
	if (group1 == NULL) {
		return -1;
	}

	int ret1 = EC_KEY_set_group(eckey, group1);
	if (ret1 != 1) {
		return -1;
	}

	int ret2 = EC_KEY_generate_key(eckey);
	if (ret2 != 1) {
		return -1;
	}
	const BIGNUM *key = EC_KEY_get0_private_key(eckey);
	char *str = BN_bn2hex(key);
	memcpy(keypair, str, 64);
	const EC_POINT * point = EC_KEY_get0_public_key(eckey);
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	if (EC_POINT_get_affine_coordinates_GFp(group1, point, x, y, NULL))
	{
		char *strx = BN_bn2hex(x), *stry = BN_bn2hex(y);
		memcpy(keypair + 64, strx, 64);
		memcpy(keypair + 128, stry, 64);
	}
	BN_free(x);
	BN_free(y);
	EC_GROUP_free(group1);
	EC_KEY_free(eckey);
	return 1;
}
static int getSm2Key_pem(char prikey[], unsigned int *prilen, char pubkey[], unsigned int *publen)
{
	EC_KEY *keypair = NULL;
	EC_GROUP *group1 = NULL;
	keypair = EC_KEY_new();
	if (!keypair) {
		return -1;
	}
	group1 = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
	if (group1 == NULL) {
		return -1;
	}

	int ret1 = EC_KEY_set_group(keypair, group1);
	if (ret1 != 1) {
		return -1;
	}

	int ret2 = EC_KEY_generate_key(keypair);
	if (ret2 != 1) {
		return -1;
	}
	size_t pri_len;
	size_t pub_len;

	BIO *pri = BIO_new(BIO_s_mem());
	BIO *pub = BIO_new(BIO_s_mem());

	PEM_write_bio_ECPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
	PEM_write_bio_EC_PUBKEY(pub, keypair);

	pri_len = BIO_pending(pri);
	pub_len = BIO_pending(pub);
	int ret = 0;
	if (*prilen >= pri_len && *publen >= pub_len)
	{
		BIO_read(pri, prikey, pri_len);
		BIO_read(pub, pubkey, pub_len);
		*prilen = pri_len;
		*publen = pub_len;
		ret = 1;
	}
	EC_GROUP_free(group1);
	EC_KEY_free(keypair);
	BIO_free_all(pub);
	BIO_free_all(pri);
	return ret;
}
static  int  sm2Encrypt_pem(const char* pubkey, unsigned int pklen, const char* context, unsigned int clen, char* result, unsigned int *rlen)
{	
	char *key = NULL;
	int ret = 0;
	if (key=OPENSSL_malloc(pklen+1))
	{
		memcpy(key, pubkey, pklen);
		key[pklen] = 0;
		BIO *pub = BIO_new(BIO_s_mem());
		BIO_puts(pub, key);
		EC_KEY *pkey = PEM_read_bio_EC_PUBKEY(pub, NULL, NULL, NULL);
		if(pkey)
			ret = SM2_encrypt_with_recommended((const unsigned char*)context, clen, (unsigned char*)result, rlen, pkey);
		EC_KEY_free(pkey);
		BIO_free(pub);
		OPENSSL_free(key);
	}
	return ret;
}
static int  sm2Decrypt_pem(const char* prikey, unsigned int pklen,const char* context, unsigned int clen, char* result, unsigned int *rlen)
{
	int ret = 0;
	char *key = NULL;
	if (key = OPENSSL_malloc(pklen + 1))
	{
		memcpy(key, prikey, pklen);
		key[pklen] = 0;
		BIO *pri = BIO_new(BIO_s_mem());
		BIO_puts(pri, key);
		EC_KEY *pkey = PEM_read_bio_ECPrivateKey(pri, NULL, NULL, NULL);
		if(pkey)
			ret = SM2_decrypt_with_recommended((const unsigned char*)context, clen, (unsigned char*)result, rlen, pkey);
		BIO_free(pri);
		EC_KEY_free(pkey);
		OPENSSL_free(key);
	}
	return ret;
}
static int sm2sign(EC_KEY *ec_key,const char* id,char* context, unsigned int contextlen,unsigned char *out,unsigned int* outlen)
{
	int ret=0,len=0;
	const EVP_MD *md = EVP_sm3();
	unsigned char buf[1024];
	size_t siz = sizeof(buf);
	unsigned int ulen = sizeof(buf);
	EVP_MD_CTX *md_ctx = NULL;
	ECDSA_SIG *sig = NULL;	
	if (!(md_ctx = EVP_MD_CTX_new())
		|| !EVP_DigestInit_ex(md_ctx, md, NULL)
		|| !SM2_compute_id_digest(md, id, strlen(id), buf, &siz, ec_key)
		|| !EVP_DigestUpdate(md_ctx, buf, siz)
		|| !EVP_DigestUpdate(md_ctx, context, contextlen)) {
		goto end;
	}
	memset(buf,0,ulen);
	if (!EVP_DigestFinal_ex(md_ctx, buf, &ulen)) {
		goto end;
	}
	len = (int)ulen;
	unsigned char *p = buf;
	if (!(sig = SM2_do_sign(buf, len, ec_key))
		|| (len = i2d_ECDSA_SIG(sig, &p)) <= 0) {
		goto end;
	}
	if(len<=*outlen)
	{
		ret = 1;
		*outlen=len;
		memcpy(out,buf,len);
	}
end:
	EVP_MD_CTX_free(md_ctx);
	ECDSA_SIG_free(sig);	
	return ret;
}
static int sm2_Sign(const char* prikey,const char* id,char* context, unsigned int contextlen,unsigned char *out,unsigned int* outlen)
{
	EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
	int ret=0;
	if (setPriKey(prikey,&ec_key,1))
		ret=sm2sign(ec_key,id,context,contextlen,out,outlen);
	EC_KEY_free(ec_key);	
	return ret;
}
static int sm2_SignPem(const char* prikey,const char* id,char* context, unsigned int contextlen,unsigned char *out,unsigned int* outlen)
{	
	BIO *pri = BIO_new(BIO_s_mem());
	BIO_puts(pri, prikey);
	EC_KEY *pkey = PEM_read_bio_ECPrivateKey(pri, NULL, NULL, NULL);
	int ret=0;
	if(pkey)
		ret = sm2sign(pkey,id,context,contextlen,out,outlen);
	EC_KEY_free(pkey);
	BIO_free(pri);	
	return ret;
}
static int sm2verify(EC_KEY *ec_key,const char* id, char* context, unsigned int contextlen, char *sig,unsigned int siglen)
{
	const EVP_MD *md = EVP_sm3();
	EVP_MD_CTX *md_ctx = NULL;
	unsigned char *sigbuf = (unsigned char *)sig;
	unsigned char buf[1024];
	size_t siz = sizeof(buf);
	unsigned int ulen = sizeof(buf);
	int ret=0;
	if (!(md_ctx = EVP_MD_CTX_new())
		|| !EVP_DigestInit_ex(md_ctx, md, NULL)
		|| !SM2_compute_id_digest(md, id, strlen(id), buf, &siz, ec_key)
		|| !EVP_DigestUpdate(md_ctx, buf, siz)
		|| !EVP_DigestUpdate(md_ctx, context, contextlen)) {
		goto end;
	}
	memset(buf,0,ulen);
	if (!EVP_DigestFinal_ex(md_ctx, buf, &ulen)) {
		goto end;
	}
	/* SM2_verify() can check no suffix on signature */
	ret = SM2_verify(NID_undef, buf, ulen, sigbuf, siglen, ec_key);	
end:	
	EVP_MD_CTX_free(md_ctx);
	return ret;	
}
static  int sm2_Verify(const char* pubkey,const char* id, char* context, unsigned int contextlen, char *sig,unsigned int siglen)
{
	EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
	int ret=0;
	if(setPubKey(pubkey,&ec_key))
		ret=sm2verify(ec_key,id,context,contextlen,sig,siglen);
	EC_KEY_free(ec_key);
	return ret;
}
static  int sm2_VerifyPem(const char* pubkey,const char* id, char* context, unsigned int contextlen, char *sig,unsigned int siglen)
{
	int ret=0;
	BIO *pub = BIO_new(BIO_s_mem());
	BIO_puts(pub, pubkey);
	EC_KEY *ec_key = PEM_read_bio_EC_PUBKEY(pub, NULL, NULL, NULL);
	if(ec_key)
		ret=sm2verify(ec_key,id,context,contextlen,sig,siglen);
	EC_KEY_free(ec_key);
	BIO_free(pub);
	return ret;
}
static int setPubKey(const char *pubkey,EC_KEY** pkey)
{
	if(!pkey||!pubkey)
		return 0;
	BIGNUM *x = BN_new(); //生成一个BIGNUM
	BN_clear(x);
	BIGNUM *y = BN_new(); //生成一个BIGNUM
	BN_clear(y);
	char keyx[65] = { 0 }, keyy[65] = { 0 };
	memcpy(keyx, pubkey, 64);
	memcpy(keyy, pubkey + 64, 64);
	BN_hex2bn(&x, keyx);
	BN_hex2bn(&y, keyy);
	int ret=EC_KEY_set_public_key_affine_coordinates(*pkey, x, y);
	BN_free(x);
	BN_free(y);
	return ret;
}
static int setPriKey(const char *prikey,EC_KEY** pkey, int issetpubkey)
{
	BIGNUM *k = BN_new(); //生成一个BIGNUM
	BN_clear(k);
	char keybuff[65] = { 0 };
	memcpy(keybuff,prikey,64);
	BN_hex2bn(&k, keybuff);
	int ret =EC_KEY_set_private_key(*pkey, k);
	if (ret&&issetpubkey)
	{
		ret = 0;
		const EC_GROUP* group= EC_KEY_get0_group(*pkey);
		if (group)
		{
			EC_POINT* pubpoint = EC_POINT_new(group);
			if (EC_POINT_mul(group, pubpoint, k,NULL, NULL, NULL))
			{
				ret = EC_KEY_set_public_key(*pkey, pubpoint);
			}
		}
	}
	BN_free(k);
	return ret;
}
static  int  sm2Encrypt(char* pubkey,const char* context, unsigned int clen, char* result, unsigned int *rlen)
{
	EC_KEY *key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
	int ret = 0;
	if(setPubKey(pubkey,&key))
		ret = SM2_encrypt_with_recommended((const unsigned char*)context, clen, (unsigned char*)result, rlen, key);		
	EC_KEY_free(key);
	return ret;
}
static int sm2Decrypt(char* prikey, const char* context, unsigned int clen, char* result, unsigned int *rlen)
{
	EC_KEY *key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
	int ret = 0;
	if (setPriKey(prikey,&key,0))
		ret = SM2_decrypt_with_recommended((const unsigned char*)context, clen, (unsigned char*)result, rlen, key);
	EC_KEY_free(key);
	return ret;
}
static void sm3hash(char content[],int len,char hash[SM3_DIGEST_LENGTH])
{
	sm3_ctx_t ctx;
	sm3_init(&ctx);
	sm3_update(&ctx, content, len);
	sm3_final(&ctx, hash);
	memset(&ctx, 0, sizeof(sm3_ctx_t));
}
static int sm3hash_file( char path[] , int len, char hash[SM3_DIGEST_LENGTH])
{
	FILE *f;
	size_t n;
	sm3_ctx_t ctx;
	unsigned char buf[1024] = { 0 };
	char file[512] = { 0 };
	memcpy(file,path, len);
	if ((f = fopen(file, "rb")) == NULL)
		return -1;
	sm3_init(&ctx);
	while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
		sm3_update(&ctx, buf, (int)n);
	sm3_final(&ctx, hash);
	memset(&ctx, 0, sizeof(ctx));
	if (ferror(f) != 0)
	{
		fclose(f);
		return 0;
	}
	fclose(f);
	return 1;
}
static void sm3Hmac(char content[], unsigned int len, char *key, unsigned int keylen, char mac[SM3_HMAC_SIZE])
{
	sm3_hmac_ctx_t ctx;
	sm3_hmac_init(&ctx, key, keylen);
	sm3_hmac_update(&ctx, content, len);
	sm3_hmac_final(&ctx, mac);
	memset(&ctx, 0, sizeof(ctx));
}
static int sm3Hmac_file(char path[], unsigned int len, char *key, unsigned int keylen, char mac[SM3_HMAC_SIZE])
{
	FILE *f;
	size_t n;
	sm3_hmac_ctx_t ctx;
	unsigned char buf[1024] = { 0 };
	char file[512] = { 0 };
	memcpy(file, path, len);
	if ((f = fopen(file, "rb")) == NULL)
		return -1;
	sm3_hmac_init(&ctx, key, keylen);
	while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
		sm3_hmac_update(&ctx, buf, (int)n);
	sm3_hmac_final(&ctx, mac);
	memset(&ctx, 0, sizeof(ctx));
	if (ferror(f) != 0)
	{
		fclose(f);
		return 0;
	}
	fclose(f);
	return 1;
}
static  int   sm2_DecodeprivateKey_pem(char *buff,int len, char prikey[65])
{
	char *keybuff = NULL;
	int ret = 0;
	if(keybuff = OPENSSL_malloc(len + 1))
	{
		memcpy(keybuff, buff, len);
		keybuff[len] = 0;
		BIO *pri = BIO_new(BIO_s_mem());
		BIO_puts(pri, keybuff);
		EC_KEY *pkey = PEM_read_bio_ECPrivateKey(pri, NULL, NULL, NULL);
		if (pkey)
		{
			const BIGNUM *key = EC_KEY_get0_private_key(pkey);
			char *str = BN_bn2hex(key);
			printf("key = %s\n", str);
			memcpy(prikey, str, 64);
			OPENSSL_free(str);
			EC_KEY_free(pkey);
			ret = 1;
		}
		BIO_free(pri);
		OPENSSL_free(keybuff);
	}
	return ret;
}
static  int  sm2_DecodepublicKey_pem(char * buff, int len, char pubkey[129])
{
	char *keybuff = NULL;
	int ret = 0;
	if (keybuff = OPENSSL_malloc(len + 1))
	{
		memcpy(keybuff, buff, len);
		keybuff[len] = 0;
		BIO *pri = BIO_new(BIO_s_mem());
		BIO_puts(pri, keybuff);
		EC_KEY *pkey = PEM_read_bio_EC_PUBKEY(pri, NULL, NULL, NULL);
		if (pkey)
		{
			const EC_POINT * point = EC_KEY_get0_public_key(pkey);
			BIGNUM *x = BN_new();
			BIGNUM *y = BN_new();
			if (EC_POINT_get_affine_coordinates_GFp(EC_GROUP_new_by_curve_name(NID_sm2p256v1), point, x, y, NULL))
			{
				char *strx = BN_bn2hex(x), *stry = BN_bn2hex(y);
				printf("keyx = %s\nkeyy = %s\n", strx, stry);
				memcpy(pubkey, strx, 64);
				memcpy(pubkey + 64, stry, 64);
				OPENSSL_free(strx);
				OPENSSL_free(stry);
				ret = 1;
			}
			BN_free(x);
			BN_free(y);
			EC_KEY_free(pkey);
		}
		BIO_free(pri);
		OPENSSL_free(keybuff);
	}
	return ret;
}
static  void  getSm2ErrStr(char szErrMsg[1024])
{
	ERR_load_SM2_strings();
	unsigned long ulErr = ERR_get_error(); // 获取错误号
	char *pTmp = NULL;
	pTmp = ERR_error_string(ulErr, szErrMsg); // 格式：error:errId:库:函数:原因
}
#if 0
static char hxestr[] = "0123456789ABCDEF";
static  char*  BinToHexStr(char *content, unsigned int clen, char *result, unsigned int *reslen)
{
	if (*reslen < 2 * clen)
	{
		*reslen = 0;
		return result;
	}
	memset(result, 0, *reslen);

	for (int i = 0; i < clen; i++)
	{
		unsigned char c = content[i], a = c / 16, b = c % 16;
		result[i * 2] = hxestr[a];
		result[i * 2 + 1] = hxestr[b];
	}
	*reslen = 2 * clen;
	return result;
}

static char hexs[128] = { 0 };
static  char* HexStrToBin(char *content, unsigned int clen, char *result, unsigned int *reslen)
{
	if (*reslen <=clen / 2 || clen == 0)
	{
		*reslen = 0;
		return result;
	}
	memset(result, 0, *reslen);
	if (hexs['a'] == 0)
	{
		for (int i = '0'; i <= '9'; i++)
			hexs[i] = i - '0';
		for (int i = 'a', v = 10; i <= 'f'; i++, v++)
			hexs[i] = v;
		for (int i = 'A', v = 10; i <= 'F'; i++, v++)
			hexs[i] = v;
	}
	size_t size = clen;
	if (clen % 2)
		size--;
	for (int i = 0; i < size; i += 2)
	{
		result[i / 2] = hexs[content[i]] * 16 + hexs[content[i + 1]];
	}
	*reslen = size / 2;
	if (clen % 2)
	{
		result[clen / 2] = hexs[content[clen - 1]];
		(*reslen)++;
	}
	return result;
}
#endif
JNIEXPORT jbyteArray JNICALL Java_com_sim_diskservice_Utils_SM2Util_generateKeyPair(JNIEnv *jni, jobject obj)
{
	char result[200] = { 0 };
	jbyteArray ret = NULL;
	if (getSm2Key(result, 200)&&(ret = (*jni)->NewByteArray(jni, 192)))
		(*jni)->SetByteArrayRegion(jni, ret, 0, 192, (jbyte *)result);
	return ret;
}
JNIEXPORT jbyteArray JNICALL Java_com_sim_diskservice_Utils_SM2Util_generateKeyPairPem(JNIEnv *jni, jobject obj)
{
	char pri[512] = { 0 }, pub[512] = { 0 }, result[1024] = { 0 };
	unsigned int len = 512, len1 = 512;
	jbyteArray ret = NULL;
	if (getSm2Key_pem(pri, &len, pub, &len1))
	{
		snprintf(result, sizeof(result), "%s:%s", pri, pub);
		if ((ret = (*jni)->NewByteArray(jni, strlen(result))))
			(*jni)->SetByteArrayRegion(jni, ret, 0, strlen(result), (jbyte *)result);
	}
	return ret;
}
JNIEXPORT jbyteArray JNICALL Java_com_sim_diskservice_Utils_SM2Util_encryptByte(JNIEnv *jni, jobject obj, jbyteArray pubkey, jbyteArray context)
{
	jbyteArray ret = NULL;
	const unsigned char *keybuf = NULL;
	const unsigned char *inbuf = NULL;
	unsigned char *outbuf = NULL;
	jsize jpubkeylen = (*jni)->GetArrayLength(jni, pubkey);
	jsize contextlen = (*jni)->GetArrayLength(jni, context);
	size_t outlen = 0;
	printf("jpubkeylen = %d\n", jpubkeylen);
	if(jpubkeylen!=128)
		return ret;
	if (!(keybuf = (unsigned char *)(*jni)->GetByteArrayElements(jni, pubkey, 0)))
		return ret;
	if (!(inbuf = (unsigned char *)(*jni)->GetByteArrayElements(jni, context, 0)))
		return ret;
	outlen = contextlen + 2048;
	if (!(outbuf = OPENSSL_malloc(outlen)))
		return ret;
	memset(outbuf,0, outlen);
	if (sm2Encrypt(keybuf, inbuf, contextlen, outbuf, &outlen)&& (ret = (*jni)->NewByteArray(jni, outlen)))
		(*jni)->SetByteArrayRegion(jni, ret, 0, outlen, (jbyte *)outbuf);
	OPENSSL_free(outbuf);
	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_sim_diskservice_Utils_SM2Util_decryptByte(JNIEnv *jni, jobject obj, jbyteArray prikey, jbyteArray context)
{
	jbyteArray ret = NULL;
	const unsigned char *keybuf = NULL;
	const unsigned char *inbuf = NULL;
	unsigned char *outbuf = NULL;
	jsize jprikeylen = (*jni)->GetArrayLength(jni, prikey);
	jsize contextlen = (*jni)->GetArrayLength(jni, context);
	size_t outlen = 0;
	printf("jprikeylen = %d contextlen=%d\n", jprikeylen, contextlen);
	if (jprikeylen != 64)
		return ret;
	if (!(keybuf = (unsigned char *)(*jni)->GetByteArrayElements(jni, prikey, 0)))
		return ret;
	if (!(inbuf = (unsigned char *)(*jni)->GetByteArrayElements(jni, context, 0)))
		return ret;
	outlen = contextlen;
	if (!(outbuf = OPENSSL_malloc(outlen)))
		return ret;
	memset(outbuf, 0, outlen);
	if (sm2Decrypt(keybuf, inbuf, contextlen, outbuf, &outlen) && (ret = (*jni)->NewByteArray(jni, outlen)))
		(*jni)->SetByteArrayRegion(jni, ret, 0, outlen, (jbyte *)outbuf);
	OPENSSL_free(outbuf);
	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_sim_diskservice_Utils_SM2Util_encryptBytePem(JNIEnv *jni, jobject obj, jbyteArray pubkey, jbyteArray arr)
{
	jbyteArray ret = NULL;
	const unsigned char *keybuf = NULL;
	const unsigned char *inbuf = NULL;
	unsigned char *outbuf = NULL;
	jsize jpubkeylen = (*jni)->GetArrayLength(jni, pubkey);
	jsize contextlen = (*jni)->GetArrayLength(jni, arr);
	size_t outlen = 0;
	if (!(keybuf = (unsigned char *)(*jni)->GetByteArrayElements(jni, pubkey, 0)))
		return ret;
	if (!(inbuf = (unsigned char *)(*jni)->GetByteArrayElements(jni, arr, 0)))
		return ret;
	outlen = contextlen + 2048;
	if (!(outbuf = OPENSSL_malloc(outlen)))
		return ret;
	printf("jpubkeylen = %d\n", jpubkeylen);
	memset(outbuf, 0, outlen);
	if (sm2Encrypt_pem(keybuf, jpubkeylen, inbuf, contextlen, outbuf, &outlen)&& (ret = (*jni)->NewByteArray(jni, outlen)))
		(*jni)->SetByteArrayRegion(jni, ret, 0, outlen, (jbyte *)outbuf);
	OPENSSL_free(outbuf);
	return ret;
}
JNIEXPORT jbyteArray JNICALL Java_com_sim_diskservice_Utils_SM2Util_decryptBytePem
(JNIEnv *jni, jobject obj, jbyteArray prikey, jbyteArray arr)
{
	jbyteArray ret = NULL;
	const unsigned char *keybuf = NULL;
	const unsigned char *inbuf = NULL;
	unsigned char *outbuf = NULL;
	jsize jprikeylen = (*jni)->GetArrayLength(jni, prikey);
	jsize contextlen = (*jni)->GetArrayLength(jni, arr);
	size_t outlen = 0;
	printf("jprikeylen = %d contextlen=%d\n", jprikeylen, contextlen);
	if (!(keybuf = (unsigned char *)(*jni)->GetByteArrayElements(jni, prikey, 0)))
		return ret;
	if (!(inbuf = (unsigned char *)(*jni)->GetByteArrayElements(jni, arr, 0)))
		return ret;
	outlen = contextlen;
	if (!(outbuf = OPENSSL_malloc(outlen)))
		return ret;
	memset(outbuf, 0, outlen);
	if (sm2Decrypt_pem(keybuf, jprikeylen, inbuf, contextlen, outbuf, &outlen) && (ret = (*jni)->NewByteArray(jni, outlen)))
		(*jni)->SetByteArrayRegion(jni, ret, 0, outlen, (jbyte *)outbuf);
	OPENSSL_free(outbuf);
	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_sim_diskservice_Utils_SM2Util_sm2DecodeprivateKeyPem(JNIEnv *jni, jobject obj, jbyteArray str)
{
	jbyteArray ret = NULL;
	const unsigned char *inbuf = NULL;
	jsize contextlen = (*jni)->GetArrayLength(jni, str);
	if (!(inbuf = (unsigned char *)(*jni)->GetByteArrayElements(jni, str, 0)))
		return ret;
	char outbuff[65] = { 0 };
	if (sm2_DecodeprivateKey_pem(inbuf, contextlen, outbuff)&&(ret = (*jni)->NewByteArray(jni, 64)))
		(*jni)->SetByteArrayRegion(jni, ret, 0, 64, (jbyte *)outbuff);
	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_sim_diskservice_Utils_SM2Util_sm2DecodepublicKeyPem(JNIEnv *jni, jobject obj, jbyteArray str)
{
	jbyteArray ret = NULL;
	const unsigned char *inbuf = NULL;
	jsize contextlen = (*jni)->GetArrayLength(jni, str);
	if (!(inbuf = (unsigned char *)(*jni)->GetByteArrayElements(jni, str, 0)))
		return ret;
	char outbuff[129] = { 0 };
	if (sm2_DecodepublicKey_pem(inbuf, contextlen, outbuff) && (ret = (*jni)->NewByteArray(jni, 128)))
		(*jni)->SetByteArrayRegion(jni, ret, 0, 128, (jbyte *)outbuff);
	return ret;
}
JNIEXPORT jstring JNICALL Java_com_sim_diskservice_Utils_SM2Util_getSm2ErrStr
(JNIEnv *jni, jobject obj)
{
	char result[1024] = { 0 };
	getSm2ErrStr(result);
	return (*jni)->NewStringUTF(jni, result);
}
JNIEXPORT jbyteArray JNICALL Java_com_sim_diskservice_Utils_SM2Util_sm3hash
(JNIEnv *jni, jobject obj, jbyteArray arr)
{
	jbyteArray ret = NULL;
	const unsigned char *inbuf = NULL;
	jsize contextlen = (*jni)->GetArrayLength(jni, arr);
	if (!(inbuf = (unsigned char *)(*jni)->GetByteArrayElements(jni, arr, 0)))
		return ret;
	char buff[SM3_DIGEST_LENGTH] = { 0 };
	sm3hash(inbuf, contextlen, buff);
	if(ret = (*jni)->NewByteArray(jni, SM3_DIGEST_LENGTH))
		(*jni)->SetByteArrayRegion(jni, ret, 0, SM3_DIGEST_LENGTH, (jbyte *)buff);
	return ret;
}
JNIEXPORT jbyteArray JNICALL Java_com_sim_diskservice_Utils_SM2Util_sm3Filehash
(JNIEnv *jni, jobject obj, jbyteArray name)
{

	jbyteArray ret = NULL;
	const unsigned char *inbuf = NULL;
	jsize contextlen = (*jni)->GetArrayLength(jni, name);
	if (!(inbuf = (unsigned char *)(*jni)->GetByteArrayElements(jni, name, 0)))
		return ret;
	char buff[SM3_DIGEST_LENGTH] = { 0 };
	if (sm3hash_file(inbuf, contextlen, buff)&&(ret = (*jni)->NewByteArray(jni, SM3_DIGEST_LENGTH)))
		(*jni)->SetByteArrayRegion(jni, ret, 0, SM3_DIGEST_LENGTH, (jbyte *)buff);
	return ret;
}
JNIEXPORT jbyteArray JNICALL Java_com_sim_diskservice_Utils_SM2Util_sm3Hmac
(JNIEnv *jni, jobject obj, jbyteArray data, jbyteArray key)
{
	jbyteArray ret = NULL;
	const unsigned char *inbuf = NULL;
	const unsigned char *keybuff = NULL;
	jsize contextlen = (*jni)->GetArrayLength(jni, data);
	jsize keylen = (*jni)->GetArrayLength(jni, key);
	if (!(inbuf = (unsigned char *)(*jni)->GetByteArrayElements(jni, data, 0)))
		return ret;
	if (!(keybuff = (unsigned char *)(*jni)->GetByteArrayElements(jni, key, 0)))
		return ret;
	char buff[SM3_DIGEST_LENGTH] = { 0 };
	sm3Hmac(inbuf, contextlen, keybuff, keylen, buff);
	if (ret = (*jni)->NewByteArray(jni, SM3_DIGEST_LENGTH))
		(*jni)->SetByteArrayRegion(jni, ret, 0, SM3_DIGEST_LENGTH, (jbyte *)buff);
	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_sim_diskservice_Utils_SM2Util_sm3FileHmac
(JNIEnv *jni, jobject obj, jbyteArray filename, jbyteArray key)
{
	jbyteArray ret = NULL;
	const unsigned char *inbuf = NULL;
	const unsigned char *keybuf = NULL;
	jsize contextlen = (*jni)->GetArrayLength(jni, filename);
	jsize keylen = (*jni)->GetArrayLength(jni, key);
	if (!(inbuf = (unsigned char *)(*jni)->GetByteArrayElements(jni, filename, 0)))
		return ret;
	if (!(keybuf = (unsigned char *)(*jni)->GetByteArrayElements(jni, key, 0)))
		return ret;
	char buff[SM3_DIGEST_LENGTH] = { 0 };
	if (sm3Hmac_file(inbuf, contextlen, keybuf, keylen,buff) && (ret = (*jni)->NewByteArray(jni, SM3_DIGEST_LENGTH)))
		(*jni)->SetByteArrayRegion(jni, ret, 0, SM3_DIGEST_LENGTH, (jbyte *)buff);
	return ret;
}
JNIEXPORT jbyteArray JNICALL Java_com_sim_diskservice_Utils_SM2Util_sign
(JNIEnv *jni, jobject obj, jbyteArray data, jbyteArray id,jbyteArray prikey)
{
	jbyteArray ret = NULL;
	const unsigned char *inbuf = NULL;
	const unsigned char *keybuf = NULL;
	const unsigned char *idbuf = NULL;
	jsize inlen = (*jni)->GetArrayLength(jni, data);
	jsize keylen = (*jni)->GetArrayLength(jni, prikey);
	jsize idlen = (*jni)->GetArrayLength(jni, id);
	if(keylen!=64||idlen>256)
		return ret;
	if (!(inbuf = (unsigned char *)(*jni)->GetByteArrayElements(jni, data, 0)))
		return ret;
	if (!(keybuf = (unsigned char *)(*jni)->GetByteArrayElements(jni, prikey, 0)))
		return ret;
	if (!(idbuf = (unsigned char *)(*jni)->GetByteArrayElements(jni, id, 0)))
		return ret;
	size_t outlen = 256;
	unsigned char outbuff[256]={0};
	char idbuff[257]={0};
	memcpy(idbuff,idbuf,idlen);
	if(sm2_Sign(keybuf,idbuff,inbuf, inlen,outbuff,&outlen)&&(ret = (*jni)->NewByteArray(jni, outlen)))
		(*jni)->SetByteArrayRegion(jni, ret, 0, outlen, (jbyte *)outbuff);
	return ret;
}
JNIEXPORT jint JNICALL Java_com_sim_diskservice_Utils_SM2Util_verify
(JNIEnv *jni, jobject obj, jbyteArray data, jbyteArray id,jbyteArray signdata,jbyteArray pubkey)
{
	jint ret=-1;
	const unsigned char *inbuf = NULL;
	const unsigned char *keybuf = NULL;
	const unsigned char *idbuf = NULL;
	char *signbuf = NULL;
	jsize inlen = (*jni)->GetArrayLength(jni, data);
	jsize keylen = (*jni)->GetArrayLength(jni, pubkey);
	jsize idlen = (*jni)->GetArrayLength(jni, id);
	jsize signlen = (*jni)->GetArrayLength(jni, signdata);
	if(keylen!=128||idlen>256)
		return ret;
	if (!(inbuf = (unsigned char *)(*jni)->GetByteArrayElements(jni, data, 0)))
		return ret;
	if (!(keybuf = (unsigned char *)(*jni)->GetByteArrayElements(jni, pubkey, 0)))
		return ret;
	if (!(idbuf = (unsigned char *)(*jni)->GetByteArrayElements(jni, id, 0)))
		return ret;
	if (!(signbuf = (char *)(*jni)->GetByteArrayElements(jni, signdata, 0)))
		return ret;
	char idbuff[257]={0};
	memcpy(idbuff,idbuf,idlen);
	ret= sm2_Verify(keybuf,idbuff, inbuf, inlen, signbuf,signlen);
	return ret;
}
JNIEXPORT jbyteArray JNICALL Java_com_sim_diskservice_Utils_SM2Util_signPem
(JNIEnv *jni, jobject obj, jbyteArray data, jbyteArray id,jbyteArray prikey)
{
	jbyteArray ret = NULL;
	const unsigned char *inbuf = NULL;
	const unsigned char *keybuf = NULL;
	const unsigned char *idbuf = NULL;
	jsize inlen = (*jni)->GetArrayLength(jni, data);
	jsize keylen = (*jni)->GetArrayLength(jni, prikey);
	jsize idlen = (*jni)->GetArrayLength(jni, id);
	if(idlen>256)
		return ret;
	if (!(inbuf = (unsigned char *)(*jni)->GetByteArrayElements(jni, data, 0)))
		return ret;
	if (!(keybuf = (unsigned char *)(*jni)->GetByteArrayElements(jni, prikey, 0)))
		return ret;
	if (!(idbuf = (unsigned char *)(*jni)->GetByteArrayElements(jni, id, 0)))
		return ret;
	size_t outlen = 256;
	unsigned char outbuff[256]={0};
	char idbuff[257]={0};
	char *keybuff=NULL;
	if (!(keybuff = OPENSSL_malloc(keylen+1)))
		return ret;
	memcpy(idbuff,idbuf,idlen);
	memcpy(keybuff,keybuf,keylen);
	keybuff[keylen]=0;
	if(sm2_SignPem(keybuff,idbuff,inbuf, inlen,outbuff,&outlen)&&(ret = (*jni)->NewByteArray(jni, outlen)))
		(*jni)->SetByteArrayRegion(jni, ret, 0, outlen, (jbyte *)outbuff);
	OPENSSL_free(keybuff);
	return ret;
}
JNIEXPORT jint JNICALL Java_com_sim_diskservice_Utils_SM2Util_verifyPem
(JNIEnv *jni, jobject obj, jbyteArray data, jbyteArray id,jbyteArray signdata,jbyteArray pubkey)
{
	jint ret=-1;
	const unsigned char *inbuf = NULL;
	const unsigned char *keybuf = NULL;
	const unsigned char *idbuf = NULL;
	char *signbuf = NULL;
	jsize inlen = (*jni)->GetArrayLength(jni, data);
	jsize keylen = (*jni)->GetArrayLength(jni, pubkey);
	jsize idlen = (*jni)->GetArrayLength(jni, id);
	jsize signlen = (*jni)->GetArrayLength(jni, signdata);
	if(idlen>256)
		return ret;
	if (!(inbuf = (unsigned char *)(*jni)->GetByteArrayElements(jni, data, 0)))
		return ret;
	if (!(keybuf = (unsigned char *)(*jni)->GetByteArrayElements(jni, pubkey, 0)))
		return ret;
	if (!(idbuf = (unsigned char *)(*jni)->GetByteArrayElements(jni, id, 0)))
		return ret;
	if (!(signbuf = (char *)(*jni)->GetByteArrayElements(jni, signdata, 0)))
		return ret;
	
	char idbuff[257]={0};
	char *keybuff=NULL;
	if (!(keybuff = OPENSSL_malloc(keylen+1)))
		return ret;
	memcpy(idbuff,idbuf,idlen);
	memcpy(keybuff,keybuf,keylen);
	memcpy(idbuff,idbuf,idlen);
	ret= sm2_VerifyPem(keybuff,idbuff, inbuf, inlen, signbuf,signlen);
	OPENSSL_free(keybuff);
	return ret;
}
JNIEXPORT jstring JNICALL Java_com_sim_diskservice_Utils_SM2Util_sm4getKey
(JNIEnv *jni, jobject obj)
{
	return NULL;
}

JNIEXPORT jbyteArray JNICALL Java_com_sim_diskservice_Utils_SM2Util_sm4encryptByte
(JNIEnv *jni, jobject obj, jbyteArray arr, jbyteArray arr1)
{
	return NULL;
}

JNIEXPORT jbyteArray JNICALL Java_com_sim_diskservice_Utils_SM2Util_sm4decryptByte
(JNIEnv *jni, jobject obj, jbyteArray arr, jbyteArray arr1)
{
	return NULL;
}
#if 0
void test()
{
	char key_result[200] = { 0 };
	getSm2Key(key_result, 200);
	char prikey[65] = { 0 };
	char pubkey[129] = { 0 };
	memcpy(prikey, key_result, 64);
	memcpy(pubkey, key_result + 64, 128);
	printf("prikey=%s length=%d\n", prikey, strlen(prikey));
	printf("pubkey=%s length=%d\n", pubkey, strlen(pubkey));
	char encrypt[1024] = { 0 }, encryptStr[1024] = { 0 }, buff[1024] = { 0 };
	char context[] = "ABCDabcdu!@#12345678";
	char decryptStr[1024] = { 0 };
	size_t encryptStrlen = 1024, decryptStrlen = 1024, encryptlen = 1024, bufflen = 1024;
	if (sm2Encrypt(pubkey, (const char*)context, strlen(context), encrypt, &encryptlen) == 0)
	{
		char szErrMsg[1024] = { 0 };
		getSm2ErrStr(szErrMsg);
		printf("sm2Encrypt err:%s\n", szErrMsg);
	}
	else
	{
		printf("encryptStr=%s\n", BinToHexStr(encrypt, encryptlen, encryptStr, &encryptStrlen));
	}
	HexStrToBin(encryptStr, encryptStrlen, buff, &bufflen);
	if (sm2Decrypt(prikey, (const char*)buff, bufflen, decryptStr, &decryptStrlen) == 0)
	{
		char szErrMsg[1024] = { 0 };
		getSm2ErrStr(szErrMsg);
		printf("sm2Encrypt err:%s\n", szErrMsg);
	}
	else
		printf("decryptStr=%s\n", decryptStr);
	
	char hmac[32]={0};
	sm3Hmac(context, strlen(context), "lxd", 3,hmac);
	encryptStrlen=sizeof(encryptStr);
	BinToHexStr(hmac,32,encryptStr, &encryptStrlen);
	encryptStr[encryptStrlen]=0;
	printf("hmac=%s\n",encryptStr);
	bufflen=sizeof(buff);
	int s = sm2_Sign(prikey, "lixudong", hmac, sizeof(hmac), buff, &bufflen);
	encryptStrlen=sizeof(encryptStr);
	BinToHexStr(buff, bufflen, encryptStr, &encryptStrlen);
	encryptStr[encryptStrlen]=0;
	printf("sm2_Sign=%d  val=%s\n", s,encryptStr);
	s=sm2_Verify(pubkey,"lixudong",hmac, sizeof(hmac),buff,bufflen);
	printf("sm2_Verify=%d\n", s); 
}

int main(int argc, char *argv[])
{
	printf("********************加、解密********************\n");
	size_t i = 1000;
	while (i)
	{
		test();
		getchar();
		i--;
	}
	getchar();
}
#endif