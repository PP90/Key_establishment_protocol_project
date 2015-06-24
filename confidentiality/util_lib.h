/*
This library contains a set of useful fuctions  for the client and server both. 

*/

#ifndef UTIL_LIB
#define UTIL_LIB 123

#define DIM_CHAR_MSG 100
#define ID_SIZE 4

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

//This function generate the first message of the protocol.
unsigned char* generate_first_msg(unsigned char* my_id, unsigned char* id_receiver, unsigned char* nonce){
	int tot_size_1st_msg=2*ID_SIZE+NONCE_SIZE;
	unsigned char* first_msg=calloc(tot_size_1st_msg, sizeof(unsigned char));
	strcat((char*)first_msg, (const char*)my_id);
	strcat((char*)first_msg,(const char*) id_receiver);
	strcat((char*) first_msg,(const char*) nonce);
	return first_msg;
}



//It prints the  message in hexadecimal mode.
void prn_hex(unsigned char* cipher_txt, int cipher_size){
	int i;
	printf("(%d bytes) ",cipher_size);
	for(i=0; i<cipher_size; i++)	printf("%02X ",cipher_txt[i]);
		
	printf("\n");
	}


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

//It returns 1 if in the message is stored the ID of this server, otherwise returns 0
int its_for_me(unsigned char* msg, unsigned char* my_id){
	int i;
	int tmp=0;
	for(i=ID_SIZE; i<ID_SIZE*2; i++){
		if(msg[i]==my_id[i-ID_SIZE]) tmp++;
		}
	if(tmp==ID_SIZE) return 1;
	else return 0;
}
#endif
