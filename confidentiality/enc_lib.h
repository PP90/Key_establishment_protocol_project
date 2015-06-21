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

	printf("Msg:\t");
	if((format==1) || (format==3))	printf("%s\n",msg);
	
	if((format==2) ||  (format==3)){ 
		for(i=0; i<strlen((const char*) msg); i++){
				printf("%02X:",msg[i]);
			}
		printf("\n");
	}
}


//It prints the encrypted message. //Maybe is not useful anymore because there is the prn_msg
void prn_enc_msg(unsigned char* cipher_txt, int cipher_size){
	int i;
	printf("Chipher text\n");
	for(i=0; i<cipher_size; i++)	printf("%02X:",cipher_txt[i]);
		
	printf("\n");
	}

//Encription function. 
//It encrypts input generic message msg, with the key knowing its length key_len and block_size.
unsigned char* enc_msg(void *msg, int block_size ,unsigned char * key, int key_len, int* cipher_len){
	int outlen=0;
	int outlen_tot=0;
	size_t msg_len=strlen(msg)+1;
	unsigned char *cipher_text=calloc(msg_len+block_size, sizeof(unsigned char));
	EVP_CIPHER_CTX* ctx=enc_initialization(key);
	
	EVP_EncryptInit(ctx,DES_ECB, key, NULL);
	EVP_EncryptUpdate(ctx,cipher_text, &outlen, (unsigned char*)msg, msg_len);
	outlen_tot+=outlen;
	
	EVP_EncryptFinal(ctx, cipher_text+outlen_tot, &outlen);//Adding padding
	outlen_tot+=outlen;
	*cipher_len=outlen_tot;
	EVP_CIPHER_CTX_cleanup(ctx);
	return cipher_text;
}


//This function decrypts the cipher text
unsigned char* dec_msg(void* cipher_text, int block_size, int cipher_size, unsigned char* key){
	EVP_CIPHER_CTX* ctx=enc_initialization(key);
	int outlen=0;
	int outlen_tot=0;
	int res=0;
	unsigned char* plain_text=calloc(cipher_size,sizeof(unsigned char));
	EVP_DecryptInit(ctx,DES_ECB, key, NULL);
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

//I'm going to create the encryption context and then encrypt with DES EBC
unsigned char* enc_msg_with_DES_EBC(void* msg, int* cipher_size){
	int key_len=EVP_CIPHER_key_length(DES_ECB);
	int block_size=EVP_CIPHER_block_size(DES_ECB);
	unsigned char* cipher_text=NULL;
	unsigned char *key=calloc(key_len, sizeof(unsigned char));
	set_key_zero(key,key_len);//I assume that this key is know by the other side, i.e. the server
	
	cipher_text=enc_msg(msg, block_size, key, key_len, cipher_size);
	free(key);
	return cipher_text;
}
