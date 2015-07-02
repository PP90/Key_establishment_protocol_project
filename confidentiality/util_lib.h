/*
This library contains a set of useful fuctions for the client and server both. 

*/


#ifndef UTIL_LIB
#define UTIL_LIB 123

#define DIM_CHAR_MSG 100
#define ID_SIZE 4

#include <sys/stat.h>
#include "hash_lib.h"

//Generates the M2 message. It's made concatening the messages
unsigned char *generate_m2(unsigned char* my_id, unsigned char* id_requestor, unsigned char* my_nonce, 	unsigned char* cipher_text, int cipher_size, int m2_size){

	unsigned char *m2=calloc(m2_size,sizeof(unsigned char));
	memcpy(m2,my_id,ID_SIZE);
	memcpy(m2+ID_SIZE,id_requestor,ID_SIZE);
	memcpy(m2+ID_SIZE+ID_SIZE,my_nonce,NONCE_SIZE);	
	memcpy(m2+ID_SIZE+ID_SIZE+NONCE_SIZE,cipher_text,cipher_size);	
	return m2;
}

//Giving the M1 protocol message, this fuction gets the id of requestor
unsigned char *get_id_requestor(unsigned char* msg){
	int i;
	unsigned char *id_requestor=calloc(ID_SIZE,sizeof(unsigned char));
	for(i=0; i<ID_SIZE; i++)	id_requestor[i]=msg[i];
	return id_requestor;
}

//Given a first protocol message, this fuction gets the nonce
unsigned char* get_nonce_other_side(unsigned char* msg){
	unsigned char* nonce_other_side=calloc(NONCE_SIZE,sizeof(unsigned char));
	int i;
	for(i=0; i<NONCE_SIZE; i++) nonce_other_side[i]=msg[ID_SIZE*2+i];
	return nonce_other_side;
}


//Return a read input message
unsigned char* read_in_msg(){
	unsigned char* msg=calloc(DIM_CHAR_MSG,sizeof(unsigned char));
	printf("Enter message:");
	fgets((char*)msg,DIM_CHAR_MSG,stdin);
	return msg;
}

//It prints the message size in byte and the message in hexadecimal mode.
void prn_hex(unsigned char* msg, int msg_size){
	int i=0;
	
	printf("(%d bytes) ",msg_size);
	for(i=0; i<msg_size; i++)	printf("%02X ",msg[i]);

	printf("\n");
	}

//This function generate the first message of the protocol with message concatenating
unsigned char* generate_first_msg(int m1_size, unsigned char* my_id, unsigned char* id_receiver, unsigned char* nonce){
	unsigned char* m1=calloc(m1_size, sizeof(unsigned char));
	memcpy(m1, my_id, ID_SIZE);
	memcpy(m1+ID_SIZE, id_receiver, ID_SIZE);
	memcpy(m1+2*ID_SIZE, nonce, NONCE_SIZE);
	return m1;
}
//Giving M2 protocol message in input, this function extracts the ecrypted part
unsigned char * get_encrypted_session_key(unsigned char* m2, int m2_len){//
	int i;
	int secret_size=m2_len-2*ID_SIZE-NONCE_SIZE;
	unsigned char *cipher_text=calloc(secret_size, sizeof(unsigned char));
	int start=ID_SIZE+ID_SIZE+NONCE_SIZE;
	int end_secret=start+secret_size;
	for(i=start; i<end_secret; i++){
		cipher_text[i-start]=m2[i];
	}
	return cipher_text;
}

//It returns 1 if in the message is stored the ID of the server, otherwise returns 0
int its_for_me(unsigned char* msg, unsigned char* my_id){
	int i=0;
	int tmp=0;
	for(i=ID_SIZE; i<ID_SIZE*2; i++){
		if(msg[i]==my_id[i-ID_SIZE]) tmp++;
		}
	if(tmp==ID_SIZE) return 1;
	else return 0;
}

//The client session.
//After receiving the first message from the server, he reply to the message and then waits for another message. It's an infinite loop.
void session_client(int sock, int block_size, unsigned char* session_key, int key_size){
	
	int ct_size=16;//Minimum dimension of cipher text
	unsigned char *ct_rec=calloc(ct_size, sizeof(unsigned char));
	unsigned char *digest=calloc(DIGEST_LEN, sizeof(unsigned char));
		//To be initialize
	unsigned char *pt=NULL;
	unsigned char* input=NULL;
	unsigned char *to_send=NULL;

	int input_size=0;
while(1){
	
	memset(ct_rec,0,ct_size);
	if(recv(sock, &ct_size,sizeof(int),0)<0){
		printf("Error receiving size message\n");
		return;	
	}
	
	ct_rec=realloc(ct_rec, ct_size);
	
		if(recv(sock, ct_rec,ct_size,0)<0){
		printf("Error receiving message from server\n");
		return;
	}
	
	printf("CT received\t");prn_hex(ct_rec,ct_size);
	pt=dec_msg(ct_rec,block_size, ct_size, session_key, AES_128_BIT_MODE);
	check_hash(pt,strlen(pt));
		
	input=read_in_msg();
	input_size=strlen(input);
	ct_size=0;
	digest=sha256_hash(input, input_size);
	to_send=realloc(to_send,DIGEST_LEN+input_size);

	memcpy(to_send, digest, DIGEST_LEN);
	memcpy(to_send+DIGEST_LEN, input, input_size);

	unsigned char * ct=enc_msg(to_send,block_size ,session_key,key_size, &ct_size,AES_128_BIT_MODE);
	memset(to_send,0,DIGEST_LEN+input_size);//I clean the to send
	if(send_msg(sock, &ct_size,sizeof(int),MEMSET_NO)<0){
		printf("Error sending size message\n");
		return;
	}

	if(send_msg(sock,ct,ct_size,MEMSET_YES)<0){
	printf("Error sending message\n");
	return;
	}
}

}

//The server session.
//After sending the first message to the client, he waits the message and then reply with an input message. It's an infinite loop.
void session_server(int sock, int block_size, unsigned char* session_key, int key_size){

	unsigned char *digest=calloc(DIGEST_LEN, sizeof(unsigned char));
	unsigned char *to_send=NULL;//To be initializate and sort out
	unsigned char * ct=NULL;
	unsigned char * ct_rec=NULL;
	int input_size=0;
	int cipher_size=0;
	unsigned char* input=NULL;
	
	while(1){
	cipher_size=0;
	input=read_in_msg();
	input_size=strlen(input);
	digest=sha256_hash(input, input_size);
	to_send=realloc(to_send,DIGEST_LEN+input_size);

	strcat((char*)to_send, (const char*)digest);//Change with memcpy
	strcat((char*)to_send, (const char*)input);

	memset(digest,0,DIGEST_LEN);//I clean the digest
	printf("TO SEND\t");prn_hex(to_send, DIGEST_LEN+input_size);
	ct=enc_msg(to_send,block_size ,session_key,key_size, &cipher_size,AES_128_BIT_MODE);
	memset(to_send,0,DIGEST_LEN+input_size);//I clean the to send
	//unsigned char * pt=dec_msg(ct,block_size, cipher_size, session_key, AES_128_BIT_MODE);//Consistency proof debug
	printf("CT:\t");prn_hex(ct,cipher_size);

	if(send_msg(sock, &cipher_size,sizeof(int),MEMSET_NO)<0){
		printf("Error sending size message\n");
		return;
	}

	if(send_msg(sock,ct,cipher_size,MEMSET_YES)<0){
		printf("Error sending message\n");
		return;
	}	
	ct=NULL;
	//Now I wait the size message and the message itself
	if(recv(sock, &cipher_size,sizeof(int),0)<=0){
		printf("Error receiving size message\n");
		return;	
		}
		ct_rec=realloc(ct_rec, cipher_size);

		if(recv(sock, ct_rec,cipher_size,0)<=0){
		printf("Error receiving size message\n");
		return;
		}
		prn_hex(ct_rec,cipher_size);
		unsigned char* pt=dec_msg(ct_rec,block_size, cipher_size, session_key, 128);
		check_hash(pt,strlen(pt));
		//memset on ct_rec
}
}


//Check if the nonce in the message it's the its own.
int its_fresh(unsigned char* msg, int session_key_size, unsigned char* my_nonce){
int end_msg=session_key_size+NONCE_SIZE;
	int tmp=0;
	int i=0;
for(i=session_key_size; i<end_msg; i++){
		if(msg[i]==my_nonce[i-session_key_size])tmp++;
	}
if(tmp==NONCE_SIZE) return 1;
else return 0;
}

//This functions get the session key from the decrypted message msg
unsigned char* extract_session_key(unsigned char* msg, int session_key_size){
int i;
unsigned char* session_key=calloc(session_key_size, sizeof(unsigned char));
for(i=0; i<session_key_size; i++){
		session_key[i]=msg[i];
	}
	return session_key;
}

//Protocol server.
//See the documentation for more details.
unsigned char* protocol_server(int client_sock, unsigned char* my_id, unsigned char* secret, int secret_size, int block_size, int key_size){

	//MEssages protocol size
	int m1_size=ID_SIZE+ID_SIZE+NONCE_SIZE;
	int m2_size=ID_SIZE+ID_SIZE+NONCE_SIZE+secret_size;
	int m3_size=key_size;
	int res_crypto_memcmp=0;
	//NONCES
	unsigned char* my_nonce=calloc(NONCE_SIZE, sizeof(unsigned char));
	unsigned char* nonce_other_side=calloc(NONCE_SIZE, sizeof(unsigned char));
	unsigned char* id_requestor=calloc(ID_SIZE,sizeof(unsigned char));
	
	//Variables for the protocol messages
	unsigned char *m1=calloc(m1_size, sizeof(unsigned char));
	unsigned char *m2=calloc(m2_size, sizeof(unsigned char));
	unsigned char *m3=calloc(m3_size, sizeof(unsigned char));	

	//Session key, CT and PT for the protocol
	unsigned char *session_key=calloc(key_size,sizeof(unsigned char));;
	unsigned char *cipher_text=calloc(secret_size,sizeof(unsigned char));
	unsigned char *plain_text=calloc(key_size+NONCE_SIZE,sizeof(unsigned char));
	unsigned char *nonce_confirmation=calloc(NONCE_SIZE, sizeof(unsigned char));
	int cipher_size=0;
	
	//I'm waiting for the client message M1
	if(recv(client_sock,m1,m1_size,0)<0){
		printf("Error receiving 1st message\n");
		return NULL;
	}
	//I check if is actually for me and...
	if(its_for_me(m1,my_id)==0){
		printf("Error: the message it's not for me.\n");
		return NULL;
		}
	//...and if the message is for me, I get the client nonce, generate the session key and generate the M2 protocol message.
	my_nonce=generate_nonce();
	id_requestor=get_id_requestor(m1);
	nonce_other_side=get_nonce_other_side(m1);
	session_key=generate_session_key(key_size);
	
	//Debug prints
	printf("Secret\t"); prn_hex(secret,secret_size);
	printf("My nonce\t"); prn_hex(my_nonce,NONCE_SIZE);
	printf("Nonce Client\t");prn_hex(nonce_other_side,NONCE_SIZE);	printf("\n");
	printf("Session key\t");prn_hex(session_key, key_size);	printf("\n");
	printf("M1:\t"); prn_hex(m1,m1_size);printf("\n");

	//I concatenate with memcopy the session key and nonce. Then it will be encrypted. At least the M2 is generate with respective function.
	memcpy(plain_text, session_key, key_size);
	memcpy(plain_text+key_size, nonce_other_side, NONCE_SIZE);

	cipher_text=enc_msg(plain_text, block_size, secret, secret_size, &cipher_size,AES_256_BIT_MODE);
	m2=generate_m2(my_id, id_requestor, my_nonce, cipher_text, cipher_size, m2_size);

	//Debug prints
	printf("M2_PART (PT)\t"); prn_hex(plain_text, key_size+NONCE_SIZE);
	printf("M2_PART (CT):\t");prn_hex(cipher_text,cipher_size);printf("\n");
	printf("M2: (CT)\t");prn_hex(m2,m2_size);	printf("\n");

	//I'll send M2
	if(send_msg(client_sock,m2,m2_size,MEMSET_YES)<0){
	printf("Error during sending M2\n");
	}

	//I'm waiting for M3	
	if(recv(client_sock,m3, m3_size,0)<0){
		printf("Error receiving M3\n");
		return NULL;
	}
	//Debug prints
	
	nonce_confirmation=dec_msg(m3, block_size, m3_size, session_key,AES_128_BIT_MODE);
	printf("M3 (ENC)\t");prn_hex(m3,m3_size);	
	printf("M3 (DEC)\t");prn_hex(nonce_confirmation,NONCE_SIZE);

	
	//Secure memcmp. It's used in order to avoid timing attack.
	res_crypto_memcmp=CRYPTO_memcmp(nonce_confirmation, my_nonce, NONCE_SIZE);
	if(res_crypto_memcmp!=0){
		printf("Nonce received it's not fresh\n");
		return NULL;
	}
	
	//Free stuff
	memset(id_requestor,0,ID_SIZE);
	free(id_requestor);
	
	memset(nonce_other_side,0,NONCE_SIZE);
	free(nonce_other_side);
	
	memset(my_nonce,0,NONCE_SIZE);
	free(my_nonce);
	
	memset(m1,0,m1_size);
	free(m1);

	memset(m2,0,m2_size);
	free(m2);

	memset(m3,0,m3_size);
	free(m3);
	
	memset(secret,0,secret_size);
	free(secret);
	
	return session_key;
}

//Protocol client.
//See the documentation for more details.
unsigned char* protocol_client(int sock, unsigned char* my_id,unsigned char* id_server, unsigned char* secret, int secret_size, int block_size, int key_size){

	//Size messages
	int m1_size=ID_SIZE+ID_SIZE+NONCE_SIZE;	
	int m2_size=ID_SIZE+ID_SIZE+NONCE_SIZE+secret_size;
	int cipher_size=0;		
	
	//Nonces
	unsigned char* my_nonce=calloc(NONCE_SIZE, sizeof(unsigned char));
	unsigned char* nonce_other_side=calloc(NONCE_SIZE,sizeof(unsigned char));

	//Messages	
	unsigned char *m1=calloc(m1_size,sizeof(unsigned char));
	unsigned char* m2=calloc(m2_size,sizeof(unsigned char));	

	//Session key, PT and CT. 
	unsigned char *cipher_text=calloc(secret_size,sizeof(unsigned char));
	unsigned char* plain_text=calloc(NONCE_SIZE+key_size,sizeof(unsigned char));//The PT in which is present the Key and the nonce
	unsigned char* session_key=calloc(key_size,sizeof(unsigned char));;
	
	my_nonce=generate_nonce();
	m1=generate_first_msg(m1_size, my_id, id_server, my_nonce);	
	printf("M1\t"); prn_hex(m1,m1_size);

	//After generate the 1st message, I'll send it
	if(send_msg(sock, m1,m1_size,MEMSET_YES)<0){
		printf("Error sending message M1\n");
		return NULL;
		}

	//I wait for m2
	if(recv(sock, m2,m2_size,0)<0){
		printf("Error receiving message M2 from the server\n");
		return NULL;
		}	

	//Clients checks m2 content
	if(its_for_me(m2, my_id)==0){
		printf("M2 it's not for me\n");
		return NULL;
	}

	//I decrypt with the secret the m2 encrypted content
	cipher_text=get_encrypted_session_key(m2,m2_size);
	nonce_other_side=get_nonce_other_side(m2); //Check on nonce of other side

	//Print some info
	printf("Secret\t");	prn_hex(secret,secret_size); printf("\n");
	printf("My nonce\t");	prn_hex(my_nonce,NONCE_SIZE);
	printf("Nonce server\t");prn_hex(nonce_other_side,NONCE_SIZE);printf("\n");
	printf("\nM2:\t");prn_hex(m2, m2_size);
	printf("Cipher_text from server\t");prn_hex(cipher_text,secret_size);
	
	//I decrypt the info and check its freshness
	plain_text=dec_msg(cipher_text, block_size, secret_size, secret,256);

	if(its_fresh(plain_text,key_size,my_nonce)==0)
		printf("Error: The nonce it's not fresh. Maybe the message is corrupted\n");
	
	//I get the session key from the plain text
	session_key=extract_session_key(plain_text, key_size);

	printf("\nSession_key:\t");prn_hex(session_key, key_size);

	unsigned char* tmp_cipher_text=enc_msg(nonce_other_side,block_size ,session_key,key_size, &cipher_size,128);
	printf("M3 (ENC)\t"); prn_hex(tmp_cipher_text,cipher_size);
	if(send_msg(sock, tmp_cipher_text,cipher_size,MEMSET_NO)<0){//Send an ecrypted message for key confirmation
		printf("Error sending message M3\n");
		return NULL;
	}
	//Free stuff
	memset(m1,0,m1_size);
	free(m1);

	memset(m2,0,m2_size);
	free(m2);

	memset(my_nonce,0,NONCE_SIZE);
	free(my_nonce);

	memset(nonce_other_side,0,NONCE_SIZE);
	free(nonce_other_side);
	
	memset(secret,0,secret_size);
	free(secret);

	return session_key;

}

// These defines helps in simplifying the example writing
#define SA struct sockaddr

// Uncomment the following macro to perform block by block decryption
//#define USE_BLOCKS


//Function to retrieve the shared secret in a file "sk"

unsigned char* retrieve_secret(unsigned char* pwd, const int secret_size) {
    
    unsigned char* secret=calloc(secret_size, sizeof(unsigned char));
    int ret;
    FILE* file;
    struct stat info;
    
    ret = stat("sk_file", &info);
    if (ret != 0)
        return NULL; // if file dosen't exist return 1
    
    file = fopen("sk_file", "r");
    if(!file){
        fprintf(stderr, "\nError opening the file sk\n"); // error in the opening file
        return NULL;
    }
    
    ret = fread(secret, 1, secret_size, file);
    if(ret != secret_size){
        fprintf(stderr, "\nError reading the key file\n"); // error in the reading file
        return NULL;
    }
    fclose(file);
    
    return secret;
}

#endif
