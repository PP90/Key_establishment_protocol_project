#ifndef SESSION 
#define SESSION 1589

//The client session.
//After receiving the first message from the server, he reply to the message and then waits for another message. It's an infinite loop.
void session_client(int sock, int block_size, unsigned char* session_key, int key_size){
	
	unsigned char *ct_rec=NULL;
	unsigned char *ct=NULL;
	unsigned char *digest=calloc(DIGEST_LEN, sizeof(unsigned char));
	unsigned char *pt=NULL;
	unsigned char* input=NULL;
	unsigned char *to_send=NULL;
	int input_size=0;
	int ct_size=0;
	
	while(1){
		
		//I'm waiting for a ct size
		if(recv(sock, &ct_size,sizeof(int),0)<0){
			printf("Error receiving size message\n");
			return;	
		}
		
		//When I receive its size I wait the ct itself
		ct_rec=realloc(ct_rec, ct_size);
	
		if(recv(sock, ct_rec,ct_size,0)<0){
			printf("Error receiving message from server\n");
			return;
	}
		//When I receive the ct, I decrypt it, check it and then clean it
		printf("CT rec\t");prn_hex(ct_rec,ct_size);
		pt=dec_msg(ct_rec,block_size, ct_size, session_key, AES_128_BIT_MODE);
		check_hash(pt,strlen(pt));
		memset(ct_rec,0,ct_size);

		//Now a message input is read, compute its lenght, compute its digest.
		input=read_in_msg();
		input_size=strlen(input);
		digest=sha256_hash(input, input_size);
		to_send=realloc(to_send,DIGEST_LEN+input_size);

		//The message with its lenght is concatenated in to_send variable. Then is encrypted and sent it
		memcpy(to_send, digest, DIGEST_LEN);
		memcpy(to_send+DIGEST_LEN, input, input_size);
		ct=enc_msg(to_send,block_size ,session_key,key_size, &ct_size,AES_128_BIT_MODE);
		memset(to_send,0,DIGEST_LEN+input_size);//I clean the to_send PT
		if(send_msg(sock, &ct_size,sizeof(int),MEMSET_NO)<0){
			printf("Error sending size message\n");
			return;
		}

		if(send_msg(sock,ct,ct_size,MEMSET_YES)<0){
		printf("Error sending message\n");
		return;
		}
		memset(ct,0,ct_size);
		ct_size=0;
	}

}

//The server session.
//After sending the first message to the client, he waits the message and then reply with an input message. It's an infinite loop.
void session_server(int sock, int block_size, unsigned char* session_key, int key_size){

	unsigned char *digest=calloc(DIGEST_LEN, sizeof(unsigned char));
	unsigned char *to_send=NULL;
	unsigned char * ct_rec=NULL;
	unsigned char* pt=NULL;
	unsigned char* input=NULL;
	unsigned char * ct=NULL;
	
	int input_size=0;
	int cipher_size=0;
	
	while(1){
		//I read an input message, get the input size message, compute its digest and then put message and its digest in a string
		input=read_in_msg();
		input_size=strlen(input);
		digest=sha256_hash(input, input_size);
		to_send=realloc(to_send,DIGEST_LEN+input_size);
		memcpy(to_send, digest, DIGEST_LEN);
		memcpy(to_send+DIGEST_LEN, input, input_size);
	
		//Encrypt the to_send and then send: its size and to_send itself.
		cipher_size=0;
		ct=enc_msg(to_send,block_size ,session_key,key_size, &cipher_size,AES_128_BIT_MODE);
	//	printf("PT:\t");prn_hex(to_send, DIGEST_LEN+input_size);
	//	printf("CT:\t");prn_hex(ct,cipher_size);
	
		if(send_msg(sock, &cipher_size,sizeof(int),MEMSET_NO)<0){
			printf("Error sending size message\n");
			return;
		}
		
	
		if(send_msg(sock,ct,cipher_size,MEMSET_YES)<0){
			printf("Error sending message\n");
			return;
		}	
		//I clean some stuff for security reason
		memset(digest,0,DIGEST_LEN);
		memset(to_send,0,DIGEST_LEN+input_size);
		memset(ct,0,cipher_size);
	 
		//Now I wait the size message and the message itself
		if(recv(sock, &cipher_size,sizeof(int),0)<0){
			printf("Error receiving size message\n");
			return;	
			}
		//I realloc in order to reserve the correct space to incoming message
		ct_rec=realloc(ct_rec, cipher_size);
		pt=realloc(pt, cipher_size);
		
		if(recv(sock, ct_rec,cipher_size,0)<0){
			printf("Error receiving size message\n");
			return;
		}

		printf("CT rec\t"); prn_hex(ct_rec,cipher_size); printf("\n");
	
		pt=dec_msg(ct_rec,block_size, cipher_size, session_key, AES_128_BIT_MODE);
		check_hash(pt,strlen(pt));
		memset(pt,0,strlen(pt));
		}
}
	#endif
