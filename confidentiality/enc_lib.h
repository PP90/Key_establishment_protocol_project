#include<stdio.h> //printf
#include<string.h>    //strlen
#include<sys/socket.h>    //socket
#include<arpa/inet.h> //inet_addr
#include<openssl/bn.h>
#include<openssl/dh.h>
#include<unistd.h>
#include<openssl/evp.h>
#include<openssl/rand.h>
#include<openssl/aes.h>

#ifndef ENC_LIB 
#define ENC_LIB 1212

#define NONCE_SIZE 4//The nonce size is 4 byte

#define DES_ECB EVP_des_ecb() //Not advisable to use. Deprecated
#define AES_256_CBC EVP_aes_256_cbc() //Symmetric cipher mode used in the secret
#define AES_128_CBC EVP_aes_128_cbc() //Symmetric cipher mode used in the session

//Initialization of context encryption.
EVP_CIPHER_CTX* enc_initialization(unsigned char* key){
	EVP_CIPHER_CTX* ctx=calloc(1,sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(ctx);
	return ctx;
}


//Function to decide arbitrary the shared long term seret. My secret is all 0.
//Actually the key must be in a crypted file and not in the source code.
void set_secret_zero(unsigned char *secret, int len_secret){
	int i;
	for(i=0; i<len_secret; i++){
		secret[i]='0';		
		}
	}


//This function generates the session key between A and B. Its length is session_key_size
unsigned char* generate_session_key(int session_key_size){
	//the entropy is the malloc itslelf
	unsigned char* session_key=(unsigned char*)malloc(session_key_size*sizeof(unsigned char));
	RAND_seed(session_key,session_key_size);
	RAND_bytes(session_key,session_key_size);
	return session_key;
}

//This function initializes the size of: secret, key, and block
void enc_inizialization(int *secret_size, int *key_size, int *block_size){
	*secret_size=EVP_CIPHER_key_length(AES_256_CBC);
	*key_size=EVP_CIPHER_key_length(AES_128_CBC);
	*block_size=EVP_CIPHER_block_size(AES_256_CBC);
}

//Encryption function. 
//It encrypts input generic message msg, with the key knowing its length key_len and block_size.
//If the mode is 128 encrypt with AES 128bit
//If the mode is 128 encrypt with AES 256bit
unsigned char* enc_msg(void *msg, int block_size ,unsigned char * key, int key_len, int* cipher_len, int mode){//Put another parameter in order to specify the encryption type
	int outlen=0;
	int outlen_tot=0;
	size_t msg_len=strlen(msg)+1;
	unsigned char *cipher_text=calloc(msg_len+block_size, sizeof(unsigned char));
	EVP_CIPHER_CTX* ctx=enc_initialization(key);
	
	if(mode==128) EVP_EncryptInit(ctx,AES_128_CBC, key, NULL);
	else if(mode==256) EVP_EncryptInit(ctx,AES_256_CBC, key, NULL);
	else {
		printf("Error: choose 128 or 256 in encryption mode\n");
		return NULL;
	}

	EVP_EncryptUpdate(ctx,cipher_text, &outlen, (unsigned char*)msg, msg_len);
	outlen_tot+=outlen;
	EVP_EncryptFinal(ctx, cipher_text+outlen_tot, &outlen);//Add the padding
	outlen_tot+=outlen;
	*cipher_len=outlen_tot;
	EVP_CIPHER_CTX_cleanup(ctx);
	return cipher_text;
}


//This function decrypts the cipher text with the key
//It decrypts input generic message msg, with the key knowing its length key_len and block_size.
//If the mode is 128 decrypt with AES 128bit
//If the mode is 128 decrypt with AES 256bit
unsigned char* dec_msg(void* cipher_text, int block_size, int cipher_size, unsigned char* key, int mode){
	EVP_CIPHER_CTX* ctx=enc_initialization(key);
	int outlen=0;
	int outlen_tot=0;
	int res=0;
	unsigned char* plain_text=calloc(cipher_size,sizeof(unsigned char));

	if(mode==128) EVP_DecryptInit(ctx,EVP_aes_128_cbc(), key, NULL);
	else if(mode==256) EVP_DecryptInit(ctx,EVP_aes_256_cbc(), key, NULL);
	else {
		printf("Error: choose 128 or 256 in decryption mode\n");
		return NULL;
	}
	EVP_DecryptUpdate(ctx, plain_text, &outlen, cipher_text, cipher_size);
	outlen_tot+=outlen;	
	res=EVP_DecryptFinal(ctx,plain_text+outlen_tot, &outlen);

	if(res==0){
		printf("Error in decrypting\n");
		return NULL;
	}
	outlen_tot+=outlen;
	EVP_CIPHER_CTX_cleanup(ctx);
	return plain_text;
	}

//This function generates the nonce
unsigned char* generate_nonce(){
	unsigned char* nonce=(unsigned char*)malloc(NONCE_SIZE*sizeof(unsigned char));
	RAND_seed(nonce,NONCE_SIZE);
	RAND_bytes(nonce,NONCE_SIZE);
	return nonce;
	}
#endif
