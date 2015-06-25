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
    
    EVP_DigestInit(ctx,EVP_sha256());                     //HASH tipe implemented is EVP_sha256()
    EVP_DigestUpdate(ctx,source,source_len);              //hashes source_len bytes of data at buffer into the digest context ctx
    EVP_DigestFinal(ctx,destination,(unsigned int*)&ret); // ret contain the number of byte of data written (length of the digest). This function retrive the digest value from ctx and place it in digest


//destruction_F
    
    EVP_MD_CTX_cleanup (ctx);
    free (ctx);
    
};

#endif


//da spostare
/*
 
 ______________________ PRELEVA LA CHIAVE DA FILE_______________
 
// These defines helps in simplifying the example writing
#define SA struct sockaddr

// Uncomment the following macro to perform block by block decryption
//#define USE_BLOCKS


 Function to retrieve the symmetric key
 @param  key             output variable to return the symmetric key
 @param  key_size        input variable providing the symmetric key size (bytes)
 @return 0 in case of success, 1 otherwise
 
int retrieve_key(char* key, const int key_size) {
    
    int ret;
    FILE* file;
    struct stat info;
    
    ret = stat("key", &info);
    if (ret != 0)
        return 1;
    
    file = fopen("key", "r");
    if(!file){
        fprintf(stderr, "\nError opening the key file\n");
        return 1;
    }
    
    ret = fread(key, 1, key_size, file);
    if(ret < key_size){
        fprintf(stderr, "\nError reading the key file\n");
        return 1;
    }
    fclose(file);
    
    return 0;
}

__________________________________
 
*/