#include<stdio.h> //printf
#include<string.h>    //strlen
#include<sys/socket.h>    //socket
#include<arpa/inet.h> //inet_addr
#include<openssl/bn.h>
#include<openssl/dh.h>
#include<unistd.h>
#include<openssl/evp.h>
#include<openssl/rand.h>
#define EVP_DES_ECB EVP_des_ecb()

//Initialization of encryption
EVP_CIPHER_CTX* enc_initialization(unsigned char* key){
	EVP_CIPHER_CTX* ctx=calloc(1,sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(ctx);
	EVP_EncryptInit(ctx,EVP_DES_ECB, key, NULL);
	return ctx;
}

void set_key_zero(unsigned char *key, int len_key){
	int i;
	for(i=0; i<len_key; i++){
		key[i]='0';		
		}
	}

////It's useful ?
void del_padding(unsigned char* msg){
	int i;
	int del_pad=0;
	for(i=0; i<strlen((const char*)msg); i++){
		if((msg[i]=='\n') & (del_pad==0)) del_pad=1;
		if(del_pad==1)	msg[i]='\0';	
	}
}


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
void prn_msg2(unsigned char* msg, int len_msg, int format){
	int i;

	printf("Msg\n");
	if(format==1)	printf("%s\n",msg);
	
	if(format==2){
		for(i=0; i<len_msg; i++){
				printf("%02X:",msg[i]);
			}
		printf("\n");
	}
}

//Print a message that's a const char*
void prn_msg(const char *string, int format){
	int i=0;
	printf("Msg	");
	printf("Len_msg:%d\n",(int)strlen(string));
	if(format==1)	printf("%s\n",string);

	if(format==2){
		for(i=0; i<strlen(string); i++){
			printf("%02X:",string[i]);
		}
	printf("\n");
	}
}


//It prints the encrypted message
void prn_enc_msg(unsigned char* chipher_txt, int len_cipher){
	int i;

	printf("Chipher text\n");
	for(i=0; i<len_cipher; i++){
			printf("%02X:",chipher_txt[i]);
		}
	printf("\n");
	}


unsigned char* enc_msg(const char *msg, int block_size, EVP_CIPHER_CTX* ctx,unsigned char * key, int key_len, int* cipher_len){
	int outlen=0;
	int outlen_tot=0;
	size_t msg_len=strlen(msg);
	//int i;
	//int n_update=msg_len/key_len;
	unsigned char *cipher_text=calloc(msg_len+block_size, sizeof(unsigned char));

	EVP_EncryptUpdate(ctx,cipher_text, &outlen, (unsigned char*)msg, msg_len);
	outlen_tot+=outlen;
	
	EVP_EncryptFinal(ctx, cipher_text+outlen_tot, &outlen);//Adding padding
	outlen_tot+=outlen;
	*cipher_len=outlen_tot;
	//I print: plaintext, key and cipher text

	prn_msg(msg, 2);
	prn_key(key,key_len);	
	prn_enc_msg(cipher_text,*cipher_len);
	return cipher_text;
}

unsigned char* dec_msg(unsigned char* cipher_text, EVP_CIPHER_CTX* ctx, unsigned char *key, int block_size, int cipher_size){
	int outlen=0;
	int outlen_tot=0;
	unsigned char* plain_text=calloc(cipher_size,sizeof(unsigned char));
	
	EVP_CIPHER_CTX_init(ctx);
	EVP_DecryptInit(ctx,EVP_DES_ECB, key, NULL);

	EVP_DecryptUpdate(ctx,plain_text, &outlen, cipher_text,cipher_size);
	outlen_tot+=outlen;
	int res=EVP_DecryptFinal(ctx,plain_text+outlen_tot, &outlen);
	outlen_tot+=outlen;
	plain_text=realloc(plain_text,outlen_tot);
	printf("cipher size:%d\n",cipher_size);
	printf("outlen_tot:%d\n",outlen_tot);
	if(res==0){
		printf("ERROR IN DECRYPTING\n");
	return NULL;
	}
	return plain_text;
	}


void free_stuff(EVP_CIPHER_CTX* ctx){
	EVP_CIPHER_CTX_cleanup(ctx);
}
