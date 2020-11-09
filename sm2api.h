#ifndef SM2API_H_
#define SM2API_H_

#ifdef _WIN32
#ifdef SM2DLLEXPORT 
#define SM2_API_EXPORT __declspec(dllexport)
#else
#define SM2_API_EXPORT __declspec(dllimport)
#endif // SM2DLLEXPORT
#else
#define SM2_API_EXPORT 
#endif

#ifdef __cplusplus
extern "C" {
#endif
	SM2_API_EXPORT int    getSm2Key_pem(char prikey[], unsigned int *prilen, char pubkey[], unsigned int *publen);
	SM2_API_EXPORT int    getSm2Key(char keypair[], unsigned int len);
	SM2_API_EXPORT int    sm2Encrypt_pem(const char* pubkey, unsigned int pklen, const char* context, unsigned int clen, char* result, unsigned int *rlen);
	SM2_API_EXPORT int    sm2Decrypt_pem(const char* prikey, unsigned int pklen, const char* context, unsigned int clen, char* result, unsigned int *rlen);
	SM2_API_EXPORT int    sm2Encrypt(const char* pubkey, char* context, unsigned int clen, char* result, unsigned int *rlen);
	SM2_API_EXPORT int    sm2Decrypt(const char* prikey, char* context, unsigned int clen, char* result, unsigned int *rlen);
	SM2_API_EXPORT int    sm2_Sign(const char* prikey, const char* id, char* context, unsigned int contextlen, unsigned char *out, unsigned int* outlen);
	SM2_API_EXPORT int    sm2_SignPem(const char* prikey, const char* id, char* context, unsigned int contextlen, unsigned char *out, unsigned int* outlen);
	SM2_API_EXPORT int    sm2_Verify(const char* pubkey, const char* id, char* context, unsigned int contextlen, char *sig, unsigned int siglen);
	SM2_API_EXPORT int    sm2_VerifyPem(const char* pubkey, const char* id, char* context, unsigned int contextlen, char *sig, unsigned int siglen);
	SM2_API_EXPORT void   sm3hash(char content[], int len, char hash[32]);
	SM2_API_EXPORT int    sm3hash_file(char path[], int len, char hash[32]);
	SM2_API_EXPORT void   sm3Hmac(char content[], unsigned int len, char *key, unsigned int keylen, char mac[32]);
	SM2_API_EXPORT int    sm3Hmac_file(char path[], unsigned int len, char *key, unsigned int keylen, char mac[32]);
	SM2_API_EXPORT int    sm2_DecodeprivateKey_pem(char *buff, int len, char prikey[65]);
	SM2_API_EXPORT int    sm2_DecodepublicKey_pem(char * buff, int len, char pubkey[129]);
	SM2_API_EXPORT void	  getSm2ErrStr(char szErrMsg[1024]);
	SM2_API_EXPORT char*  binToHexStr(char *content, unsigned int clen, char *result, unsigned int *reslen);
	SM2_API_EXPORT char*  hexStrToBin(char *content, unsigned int clen, char *result, unsigned int *reslen);
#ifdef __cplusplus
}
#endif

#endif // !SM2API_H_
