#include<stdio.h> //printf
#include<string.h>    //strlen
#include<sys/socket.h>    //socket
#include<arpa/inet.h> //inet_addr
#include<openssl/bn.h>
#include<openssl/dh.h>
#include<unistd.h>
#include<openssl/evp.h>
#include<openssl/rand.h>

#define DES_ECB EVP_des_ecb()

//Initialization of context encryption
EVP_CIPHER_CTX* enc_initialization(unsigned char* key){
	EVP_CIPHER_CTX* ctx=calloc(1,sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(ctx);
	EVP_EncryptInit(ctx,DES_ECB, key, NULL);
	return ctx;
}

//Function to decide arbitrary the key. My key is all 0.
void set_key_zero(unsigned char *key, int len_key){
	int i;
	for(i=0; i<len_key; i++){
		key[i]='0';		
		}
	}

//The following four function can be aggregated in only one. TO DO
//Print the key
void prn_key(unsigned char *key, int len_key){
	int i=0;
	printf("Key:\n");
	for(i=0; i<len_key; i++){
		printf("%02X:",key[i]);
		}
	printf("\n");
}

//Print the bytes of a generic message 
void prn_msg(unsigned char* msg, int format){//If format is 1 print the string, otherwise print the hexadecimal format
	int i;

	printf("Msg\n");
	if(format==1)	printf("%s\n",msg);
	
	if(format==2){
		for(i=0; i<strlen((const char*) msg); i++){
				printf("%02X:",msg[i]);
			}
		printf("\n");
	}
}


//It prints the encrypted message. //Maybe is not useful anymore because there is the prn_msg
void prn_enc_msg(unsigned char* chipher_txt, int len_cipher){
	int i;

	printf("Chipher text\n");
	for(i=0; i<len_cipher; i++){
			printf("%02X:",chipher_txt[i]);
		}
	printf("\n");
	}

//Encription function. 
//It encrypts input generic message msg, with the key knowing its length key_len and block_size.
unsigned char* enc_msg(void *msg, int block_size ,unsigned char * key, int key_len, int* cipher_len){
	int outlen=0;
	int outlen_tot=0;
	size_t msg_len=strlen(msg);
	unsigned char *cipher_text=calloc(msg_len+block_size, sizeof(unsigned char));

	EVP_CIPHER_CTX* ctx=enc_initialization(key);
	EVP_EncryptUpdate(ctx,cipher_text, &outlen, (unsigned char*)msg, msg_len);
	outlen_tot+=outlen;
	
	EVP_EncryptFinal(ctx, cipher_text+outlen_tot, &outlen);//Adding padding
	outlen_tot+=outlen;
	*cipher_len=outlen_tot;

	//It prints: plaintext, key and cipher text
	prn_msg(msg, 2);
	prn_key(key,key_len);	
	prn_enc_msg(cipher_text,*cipher_len);
	EVP_CIPHER_CTX_cleanup(ctx);
	return cipher_text;
}


//This function decrypts the cipher text
unsigned char* dec_msg(void* cipher_text, int block_size, int cipher_size, unsigned char* key){
	EVP_CIPHER_CTX* ctx=enc_initialization(key);
	int outlen=0;
	int outlen_tot=0;
	unsigned char* plain_text=calloc(cipher_size,sizeof(unsigned char));

	EVP_DecryptInit(ctx,DES_ECB, key, NULL);

	EVP_DecryptUpdate(ctx,plain_text+block_size, &outlen, cipher_text,cipher_size);
	outlen_tot+=outlen;
	int res=EVP_DecryptFinal_ex(ctx,plain_text+outlen_tot, &outlen);
	outlen_tot+=outlen;
	plain_text=realloc(plain_text,outlen_tot);
	if(res==0){
		printf("Error in decrypting\n");
	return NULL;
	}
	EVP_CIPHER_CTX_cleanup(ctx);
	return plain_text;
	}
