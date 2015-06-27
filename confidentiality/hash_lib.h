#include<stdio.h> //printf
#include<string.h>    //strlen
#include<openssl/evp.h> //hash

#ifndef HASH_MSG
#define HASH_MSG 801

void sha256_hash(unsigned char * destination,char * source,int source_len) {
  
//context
    
    int ret;
    EVP_MD_CTX * ctx;                                     // hash context
    ctx = (EVP_MD_CTX *)malloc(sizeof(EVP_MD_CTX));       //context creation
    EVP_MD_CTX_init(ctx);                                 //initialized digest context ctx
  
//hashing_f
    
    EVP_DigestInit(ctx,EVP_sha256());                     //HASH type implemented is EVP_sha256()
    EVP_DigestUpdate(ctx,source,source_len);              //hashes source_len bytes of data at buffer into the digest context ctx
    EVP_DigestFinal(ctx,destination,(unsigned int*)&ret); // ret contain the number of byte of data written (length of the digest). This function retrive the digest value from ctx and place it in digest


//destruction_F
    
    EVP_MD_CTX_cleanup (ctx);
    free (ctx);
    
};

#endif


