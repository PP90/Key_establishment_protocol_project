#include<stdio.h>
#include<string.h>    //strlen
#include<sys/socket.h>
#include<arpa/inet.h> //inet_addr
#include<unistd.h>    //write
#include<openssl/bn.h>
#include<openssl/dh.h>


#ifndef DH_LIBRARY
#define DH_LIBRARY

#define KEY_LENGHT 512
#define DIM_CHAR_MSG 1000
#define DIM_SER_RPL_MSG 1000
#define PORT_NUMBER 8888


//It generates the public and the private key of Diffie-Hellman protocol
DH* gen_pk_and_sk(){
	DH* dh=DH_new();//It's empty initially. It's a calloc\malloc equivent.
	dh=DH_generate_parameters(KEY_LENGHT, DH_GENERATOR_2,NULL,NULL);//It generates randomly p and g
	int gen_key=DH_generate_key(dh);//It generates the secret and public keys
		if(gen_key==0){
			printf("Error during generating key\n");
			return NULL;
			}
	return dh;
	}

//It prints the info about the values of the private and public key.
void prn_get_secret(DH* dh){
	printf("P: %s\n",BN_bn2dec(dh->p));
	printf("G: %s\n",BN_bn2dec(dh->g));
	printf("Public key:%s\n",BN_bn2dec(dh->pub_key));
	printf("Private key:%s\n",BN_bn2dec(dh->priv_key));
}

BIGNUM* get_pub_key(DH *dh){
	return dh->pub_key;
}

BIGNUM* get_priv_key(DH *dh){
	return dh->priv_key;
}

#endif
