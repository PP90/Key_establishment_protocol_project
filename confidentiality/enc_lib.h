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

#define NONCE_SIZE 2
#define KEY_SESSION_SIZE 32

#define DES_ECB EVP_des_ecb()
#define AES_256_CBC EVP_aes_256_cbc()

//Initialization of context encryption. Ok
EVP_CIPHER_CTX* enc_initialization(unsigned char* key){
	EVP_CIPHER_CTX* ctx=calloc(1,sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(ctx);
	return ctx;
}

//Function to decide arbitrary the shared long term seret. My secret is all 0.
void set_secret_zero(unsigned char *secret, int len_secret){//Actually the key must be in a crypted file and not in the source code.
	int i;
	for(i=0; i<len_secret; i++){
		secret[i]='0';		
		}
	}


//This function generates the session key between A and B
unsigned char* generate_session_key(int session_key_size){
	unsigned char* session_key=calloc(session_key_size, sizeof(unsigned char));
	RAND_seed(session_key,session_key_size);
	RAND_bytes(session_key,session_key_size);
return session_key;
}

//Encription function. 
//It encrypts input generic message msg, with the key knowing its length key_len and block_size.
unsigned char* enc_msg(void *msg, int block_size ,unsigned char * key, int key_len, int* cipher_len, EVP_CIPHER *enc_type){
	int outlen=0;
	int outlen_tot=0;
	size_t msg_len=strlen(msg)+1;
	unsigned char *cipher_text=calloc(msg_len+block_size, sizeof(unsigned char));
	EVP_CIPHER_CTX* ctx=enc_initialization(key);

	EVP_EncryptInit(ctx,enc_type, key, NULL);//If I want change the encryption type, I'll change the 2nd parameter
	EVP_EncryptUpdate(ctx,cipher_text, &outlen, (unsigned char*)msg, msg_len);
	outlen_tot+=outlen;
	
	EVP_EncryptFinal(ctx, cipher_text+outlen_tot, &outlen);//Add the padding
	outlen_tot+=outlen;
	*cipher_len=outlen_tot;
	EVP_CIPHER_CTX_cleanup(ctx);
	return cipher_text;
}


//This function decrypts the cipher text
unsigned char* dec_msg(void* cipher_text, int block_size, int cipher_size, unsigned char* key, EVP_CIPHER *enc_type){
	EVP_CIPHER_CTX* ctx=enc_initialization(key);
	int outlen=0;
	int outlen_tot=0;
	int res=0;
	unsigned char* plain_text=calloc(cipher_size,sizeof(unsigned char));
	EVP_DecryptInit(ctx,enc_type, key, NULL);
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

unsigned char* generate_nonce(){
	unsigned char* nonce=calloc(NONCE_SIZE, sizeof(unsigned char));
	RAND_seed(nonce,NONCE_SIZE);
	RAND_bytes(nonce,NONCE_SIZE);
	return nonce;
	}
#endif
