#include<stdio.h> //printf
#include<string.h>    //strlen
#include<openssl/evp.h> //hash

#ifndef HASH_MSG
#define HASH_MSG 801

#define DIGEST_LEN EVP_MD_size(EVP_sha256()) //digest length

void prn_hex(unsigned char* cipher_txt, int cipher_size); // prototype print function

unsigned char* sha256_hash(char * source,int source_len) {
  
//context
    
    unsigned int ret;
    unsigned char * digest= calloc(DIGEST_LEN , sizeof(unsigned char));    // 32 elements of one byte
    
    EVP_MD_CTX * ctx;                                     // hash context
    ctx = (EVP_MD_CTX *)malloc(sizeof(EVP_MD_CTX));       //context creation
    EVP_MD_CTX_init(ctx);                                 //initialized digest context ctx
  
//hashing_f
    
    EVP_DigestInit(ctx,EVP_sha256());                     //HASH type implemented is EVP_sha256()
    EVP_DigestUpdate(ctx,source,source_len);              //hashes source_len bytes of data at buffer into the digest context ctx
    EVP_DigestFinal(ctx,digest,&ret); // ret contain the number of byte of data written (length of the digest). This function retrive the digest value from ctx and place it in digest


//destruction_F
    
    EVP_MD_CTX_cleanup (ctx);
    free (ctx);
    return digest;
    
};


//Check the integrity of the message.

int check_hash(unsigned char* msg,int msg_size){

    int i=0;
    int pt_size=msg_size-DIGEST_LEN;
    unsigned char* tmp_digest= calloc(DIGEST_LEN,sizeof(unsigned char));
    unsigned char* tmp_pt= calloc(pt_size,sizeof(unsigned char));
    unsigned char* hash_pt= calloc(DIGEST_LEN,sizeof(unsigned char));

    for(i=0;i<DIGEST_LEN;i++) { tmp_digest[i]=msg[i]; }
    for(i=DIGEST_LEN;i<msg_size;i++) { tmp_pt[i-DIGEST_LEN]=msg[i]; }
    
    hash_pt = sha256_hash(tmp_pt,pt_size);
  //  prn_hex (hash_pt,DIGEST_LEN);  //debug
   // prn_hex (tmp_digest,DIGEST_LEN); //debug
    
    if(CRYPTO_memcmp(hash_pt,tmp_digest, DIGEST_LEN)!=0){
        printf("The message is corrupted\n");
        return 0;
    }
    printf("I've received: %s", tmp_pt);
    return 1;
};


#endif


