/*
This library contains a set of useful fuctions for the client and server both. 

*/

#ifndef UTIL_LIB
#define UTIL_LIB 123

#define DIM_CHAR_MSG 100
#define ID_SIZE 4

//Generates the M2 message. It's made concatening the messages
unsigned char *generate_m2(unsigned char* id_requestor, unsigned char* my_id, unsigned char* my_nonce, 		unsigned char* cipher_text, int cipher_size, int *m2_size){
	*m2_size=2*ID_SIZE+NONCE_SIZE+cipher_size;
	unsigned char *m2=calloc(*m2_size,sizeof(unsigned char));
	strcat((char*)m2, (const char*)my_id);
	strcat((char*)m2, (const char*)id_requestor);
	strcat((char*)m2, (const char*)my_nonce);
	strcat((char*)m2, (const char*)cipher_text);
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

//This function generate the first message of the protocol with message concatenating
unsigned char* generate_first_msg(unsigned char* my_id, unsigned char* id_receiver, unsigned char* nonce){
	int tot_size_1st_msg=2*ID_SIZE+NONCE_SIZE;
	unsigned char* first_msg=calloc(tot_size_1st_msg, sizeof(unsigned char));
	strcat((char*)first_msg, (const char*)my_id);
	strcat((char*)first_msg,(const char*) id_receiver);
	strcat((char*) first_msg,(const char*) nonce);
	return first_msg;
}

//It prints the message size in byte and the message in hexadecimal mode.
void prn_hex(unsigned char* cipher_txt, int cipher_size){
	int i;
	printf("(%d bytes) ",cipher_size);
	for(i=0; i<cipher_size; i++)	printf("%02X ",cipher_txt[i]);
		
	printf("\n");
	}

//Giving M2 protocol message in input, this function extracts the ecrypted part
unsigned char * get_encrypted_session_key(unsigned char* m2, int m2_len){//
	int i;
	int secret_size=m2_len-2*ID_SIZE-NONCE_SIZE;
	unsigned char *cipher_text=calloc(secret_size, sizeof(unsigned char));
	int start=2*ID_SIZE+NONCE_SIZE;
	int end_secret=start+secret_size;
	for(i=start; i<end_secret; i++){
		cipher_text[i-start]=m2[i];
	}
	return cipher_text;
}

//It returns 1 if in the message is stored the ID of the server, otherwise returns 0
int its_for_me(unsigned char* msg, unsigned char* my_id){
	int i;
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
	unsigned char *pt=NULL;
while(1){
	
	memset(ct_rec,0,ct_size);
	if(recv(sock, &ct_size,sizeof(int),0)<=0){
		printf("Error receiving size message\n");
		return;	
	}
	
	ct_rec=realloc(ct_rec, ct_size);
	
		if(recv(sock, ct_rec,ct_size,0)<=0){
		printf("Error receiving message from server\n");
		return;
	}
	
	prn_hex(ct_rec,ct_size);
	pt=dec_msg(ct_rec,block_size, ct_size, session_key, 128);
	
	printf("I've received from server:%s\n",pt);
	unsigned char* input=read_in_msg();
	ct_size=0;
	
	unsigned char * ct=enc_msg(input,block_size ,session_key,key_size, &ct_size,128);
	if(send(sock, &ct_size,sizeof(int),MEMSET_YES)<0){
		printf("Error sending size message\n");
		return;
	}

	if(send(sock,ct,ct_size,MEMSET_NO)<0){
	printf("Error sending message\n");
	return;
	}
}

}

//The server session.
//After sending the first message to the client, he waits the message and then reply with an input message. It's an infinite loop.
void session_server(int sock, int block_size, unsigned char* session_key, int key_size){
	while(1){
	unsigned char* input=read_in_msg();
	int cipher_size=0;
	unsigned char * ct=enc_msg(input,block_size ,session_key,key_size, &cipher_size,128);
	//unsigned char * pt=dec_msg(ct,block_size, cipher_size, session_key, 128);
	printf("CT:\t");prn_hex(ct,cipher_size);
	if(send(sock, &cipher_size,sizeof(int),MEMSET_YES)<0){
		printf("Error sending size message\n");
		return;
	}
	
	if(send(sock,ct,cipher_size,MEMSET_NO)<0){
		printf("Error sending message\n");
		return;
	}
	
	if(recv(sock, &cipher_size,sizeof(int),0)<=0){
		printf("Error receiving size message\n");
		return;	
		}
		ct=realloc(ct, cipher_size);

		if(recv(sock, ct,cipher_size,0)<=0){
		printf("Error receiving size message\n");
		return;
		}
		prn_hex(ct,cipher_size);
		printf("I've received from server:%s\n",dec_msg(ct,block_size, cipher_size, session_key, 128));	
}
}


//Check if the nonce in the message it's the its own.
int its_fresh(unsigned char* msg, int session_key_size, unsigned char* my_nonce){
int end_msg=session_key_size+NONCE_SIZE;
	int tmp=0;
	int i;
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

	unsigned char* my_nonce=NULL;
	unsigned char* nonce_other_side=NULL;
	unsigned char *session_key=NULL;
	unsigned char *cipher_text=NULL;
	unsigned char *plain_text=calloc(key_size+NONCE_SIZE,sizeof(unsigned char));
	int cipher_size=0;
	unsigned char* id_requestor=calloc(ID_SIZE,sizeof(unsigned char));
	//Variables for the protocol messages
	int size_1st_msg=2*ID_SIZE+NONCE_SIZE;
	unsigned char * first_msg=calloc(size_1st_msg, sizeof(unsigned char));
	unsigned char *second_msg=NULL;
	int m2_size=0;
	int size_3rd_msg=key_size;
	unsigned char * third_msg=calloc(size_3rd_msg, sizeof(unsigned char));	

	//I'm waiting for the client
	if(recv(client_sock,first_msg,size_1st_msg,0)<0){
		printf("Error receiving 1st message\n");
		return NULL;
	}
	//I check if is actually for me and...
	if(its_for_me(first_msg,my_id)==0){
		printf("Error: the message it's not for me.\n");
		return NULL;
		}
	//...and if the message is for me, I get the client nonce, generate the session key and generate the M2 protocol message
	my_nonce=generate_nonce();
	id_requestor=get_id_requestor(first_msg);
	nonce_other_side=get_nonce_other_side(first_msg);
	session_key=generate_session_key(key_size);
	
	strcat((char*)plain_text, (const char*)session_key);
	strcat((char*)plain_text, (const char*)nonce_other_side);
	

	cipher_text=enc_msg(plain_text, block_size, secret, secret_size, &cipher_size,256);
	second_msg=generate_m2(id_requestor, my_id, my_nonce, cipher_text, cipher_size, &m2_size);

	//I'll send M2
	if(send(client_sock,second_msg,m2_size,MEMSET_NO)<0){
	printf("Error during sending M2\n");
	}

	//I'm waiting for M3	
	if(recv(client_sock,third_msg, size_3rd_msg,0)<0){
		printf("Error receiving M3\n");
		return NULL;
	}
	
	//Print about protocol
	printf("Secret\t"); prn_hex(secret,secret_size);
	printf("My nonce\t"); prn_hex(my_nonce,NONCE_SIZE);
	printf("Nonce Client\t");prn_hex(nonce_other_side,NONCE_SIZE);
	printf("\n");
	printf("Session key\t");prn_hex(session_key, key_size);
	printf("\n");
	printf("M1:\t"); prn_hex(first_msg,size_1st_msg);printf("\n");
	printf("M2_PART (PT to en)\t"); prn_hex(plain_text, key_size+NONCE_SIZE);
	printf("Part of M2 (ENC):\t");prn_hex(cipher_text,cipher_size);
	printf("\nM2: (Enc)\t");prn_hex(second_msg,m2_size);	printf("\n");

	printf("M3 (ENC)\t");prn_hex(third_msg,size_3rd_msg);
	printf("M3 (DEC)\t");prn_hex(dec_msg(third_msg, block_size, size_3rd_msg, session_key,128),4);
	//Secure memcmp
	if(CRYPTO_memcmp(dec_msg(third_msg, block_size, size_3rd_msg, session_key,128),my_nonce, NONCE_SIZE)!=0){
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
	
	memset(first_msg,0,size_1st_msg);
	free(first_msg);

	memset(second_msg,0,m2_size);
	free(second_msg);

	memset(third_msg,0,size_3rd_msg);
	free(third_msg);
	
	memset(secret,0,secret_size);
	free(secret);
return session_key;
}

//Protocol client.
//See the documentation for more details.
unsigned char* protocol_client(int sock, unsigned char* my_id,unsigned char* id_server, unsigned char* secret, int secret_size, int block_size, int key_size){

	unsigned char* my_nonce=generate_nonce();
	unsigned char* nonce_other_side=calloc(NONCE_SIZE,sizeof(unsigned char));

	unsigned char *cipher_text=NULL;
	unsigned char* plain_text=NULL;
	unsigned char* session_key=NULL;
	
	int tot_size_1st_msg=2*ID_SIZE+NONCE_SIZE+1;
	unsigned char *first_msg=generate_first_msg(my_id, id_server,my_nonce);

	int m2_size=secret_size+2*ID_SIZE+NONCE_SIZE;

	int cipher_size=0;
	unsigned char* m2=calloc(m2_size,sizeof(unsigned char));
	
	//After generate the 1st message, I'll send it
	if(send(sock, first_msg,tot_size_1st_msg,MEMSET_YES)<0){
		printf("Error sending message M1\n");
		return NULL;
		}
	//I wait for m2
	if(recv(sock, m2,m2_size,0)<0){
		printf("Error receiving message M2 from the server\n");
		return NULL;
		}	
	//I check m2 content
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
	printf("Cipher_text from server\t");prn_hex(cipher_text,32);
	
	//I decrypt the info and check its freshness
	plain_text=dec_msg(cipher_text, block_size, secret_size, secret,256);

	if(its_fresh(plain_text,key_size,my_nonce)==0)
		printf("Error: The nonce it's not fresh. Maybe the message is corrupted\n");
	
	//I get the session key from the plain text
	session_key=extract_session_key(plain_text, key_size);

	printf("\nSession_key:\t");prn_hex(session_key, key_size);

	unsigned char* tmp_cipher_text=enc_msg(nonce_other_side,block_size ,session_key,key_size, &cipher_size,128);
	printf("M3 (ENC)\t"); prn_hex(tmp_cipher_text,cipher_size);
	if(send(sock, tmp_cipher_text,cipher_size,MEMSET_NO)<0){//Send an ecrypted message for key confirmation
		printf("Error sending message M3\n");
		return NULL;
	}
	//Free stuff
	memset(first_msg,0,tot_size_1st_msg);
	free(first_msg);

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
#endif
