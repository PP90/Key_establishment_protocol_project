#include"enc_lib.h"
#include"net_lib.h"
#include"util_lib.h"

#ifndef SER_SRC 
#define SER_SRC 4332

#define DEFAULT_ID_SERVER "1234"

//Get from the message the ID of requestor
unsigned char *get_id_requestor(unsigned char* msg){
	int i;
	unsigned char *id_requestor=calloc(ID_SIZE,sizeof(unsigned char));
	for(i=0; i<ID_SIZE; i++)	id_requestor[i]=msg[i];
	return id_requestor;
}

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



int main(int argc , char *argv[]){

	unsigned char* my_id=(unsigned char*)DEFAULT_ID_SERVER;
	unsigned char* id_requestor=NULL;
	unsigned char* my_nonce=NULL;
	unsigned char* nonce_other_side=NULL;
	int size_1st_msg=2*ID_SIZE+NONCE_SIZE;
	unsigned char * first_msg=calloc(size_1st_msg, sizeof(unsigned char));
	unsigned char *session_key=NULL;
	unsigned char *m2=NULL;
	unsigned char *cipher_text=NULL;
	int secret_size;
	int key_size;
	enc_inizialization(&secret_size, &key_size);
	int block_size=EVP_CIPHER_block_size(AES_256_CBC);

	//Check on command line inputs
	if(argc==2) my_id=(unsigned char*)argv[1];

	int socket_desc , client_sock , c;
	struct sockaddr_in server , client;
	int socket_dest=0;
	int cipher_size=0;
	int m2_size=0;

	unsigned char *secret=calloc(secret_size, sizeof(unsigned char));
	set_secret_zero(secret,secret_size);
	unsigned char *plain_text=calloc(key_size+NONCE_SIZE,sizeof(unsigned char));
	
	//DA qua a..
	socket_desc = socket(AF_INET , SOCK_STREAM , 0);
	if (socket_desc == -1){
        	printf("Could not create socket");
    	}
    	puts("Socket created");
     
    //Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons( PORT_NUMBER );
    
	int optval=1;
	setsockopt(socket_desc, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)); 
    //Bind
	if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0){
        //print the error message
        	perror("bind failed. Error");
        	return 1;
    	}
    	puts("Bind done");
     //...a qua dovrebbe diventare una funzione, però è un bordello perchè ci stanno puntatori ovunque. Da fare a tempo perso

	    //Listen
	if(socket_dest<0) return -1;
    	listen(socket_desc , 3);
     
    //Accept and incoming connection
    	puts("Waiting for incoming connections...");
    	c = sizeof(struct sockaddr_in);
     
    //accept connection from an incoming client
    	client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);
   	 if (client_sock < 0){
        	perror("accept failed");
        	return 1;
    }
    puts("Connection accepted");

     	if(recv(client_sock,first_msg,size_1st_msg,0)<0){
		printf("Error receiving first message\n");
		return -1;
	}
		
	if(its_for_me(first_msg,my_id)==0){
		printf("Error: the message it's not for me.\n");
		return -1;
		}
	//If the message is for me, I get the client nonce, generate the session key and generate the M2 protocol message
	my_nonce=generate_nonce();
	id_requestor=get_id_requestor(first_msg);
	nonce_other_side=get_nonce_other_side(first_msg);
	session_key=generate_session_key(key_size);
	
	strcat((char*)plain_text, (const char*)session_key);
	strcat((char*)plain_text, (const char*)nonce_other_side);
	printf("M2_PART (DEC)\t"); prn_hex(plain_text, key_size+NONCE_SIZE);

	cipher_text=enc_msg(plain_text, block_size, secret, secret_size, &cipher_size,256);
	m2=generate_m2(id_requestor, my_id, my_nonce, cipher_text, cipher_size, &m2_size);

	if(write(client_sock,m2,m2_size)!=m2_size){//The write function returns how much bytes are written
		printf("Error during write socket\n");
		return -1;
		}

	//Some info  about the protocol
	printf("Secret\t"); prn_hex(secret,secret_size);
	printf("\n");
	printf("My nonce\t"); prn_hex(my_nonce,NONCE_SIZE);
	printf("Nonce Client\t");prn_hex(nonce_other_side,NONCE_SIZE);
	printf("\n");
	printf("Session key\t");prn_hex(session_key, key_size);
	printf("\n");
	printf("M1:\t"); prn_hex(first_msg,size_1st_msg);
	printf("\nM2: (Enc)\t");prn_hex(m2,m2_size);
	printf("\n");
	printf("Part of M2 (ENC):\t");prn_hex(cipher_text,cipher_size);
	//Consisentecy Proof
	printf("M2 (DEC)\t");
	prn_hex(dec_msg(cipher_text, block_size, cipher_size, secret,256),20);

	free(id_requestor);
	free(nonce_other_side);
	free(my_nonce);
	return 0;

}
#endif
