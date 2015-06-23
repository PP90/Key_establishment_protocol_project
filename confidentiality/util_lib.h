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

//The following three function can be aggregated in only one (?). TO DO
//Print the key
void prn_key(unsigned char *key, int len_key){
	int i=0;
	for(i=0; i<len_key; i++){
		printf("%02X:",key[i]);
		}
	printf("\n");
}

//Print the bytes of a generic message 
void prn_msg(unsigned char* msg, int format){//If format is 1 print the string, otherwise print the hexadecimal format. If format is three the fuction prints 
	int i;

	if((format==1) || (format==3))	printf("%s\n",msg);
	
	if((format==2) ||  (format==3)){ 
		for(i=0; i<strlen((const char*) msg); i++){
				printf("%02X ",msg[i]);
			}
		printf("\n");
	}
}


//It prints the encrypted message. //Maybe is not useful anymore because there is the prn_msg
void prn_enc_msg(unsigned char* cipher_txt, int cipher_size){
	int i;
	for(i=0; i<cipher_size; i++)	printf("%02X:",cipher_txt[i]);
		
	printf("\n");
	}

#endif
