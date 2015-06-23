#include"enc_lib.h"
#include"net_lib.h"
#include"util_lib.h"

#ifndef SER_SRC 
#define SER_SRC 4332

#define DEFAULT_ID_SERVER "1234"

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

//Get from the message the ID of requestor
unsigned char *get_id_requestor(unsigned char* msg){
	int i;
	unsigned char *id_requestor=calloc(ID_SIZE,sizeof(unsigned char));
	for(i=0; i<ID_SIZE; i++)	id_requestor[i]=msg[i];
	return id_requestor;
}

int main(int argc , char *argv[]){


	unsigned char* my_id=(unsigned char*)DEFAULT_ID_SERVER;
	unsigned char* id_requestor=NULL;
	unsigned char* my_nonce=NULL;
	unsigned char* nonce_other_side=NULL;
	int tot_size_1st_msg=2*ID_SIZE+NONCE_SIZE;
	unsigned char * first_msg=calloc(tot_size_1st_msg, sizeof(unsigned char));
	unsigned char *session_key=NULL;

	if(argc>=2) my_id=(unsigned char*)argv[1];
	int socket_desc , client_sock , c;
	struct sockaddr_in server , client;
	//unsigned char *cipher_text=NULL;
	//unsigned char *plain_text=NULL;
	int socket_dest=0;
	
	//int cipher_size=0;
	int secret_len=EVP_CIPHER_key_length(AES_256_CBC);
	//int block_size=EVP_CIPHER_block_size(AES_256_CBC);

	unsigned char *secret=calloc(secret_len, sizeof(unsigned char));
	set_secret_zero(secret,secret_len);
	
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

     	if(recv(client_sock,first_msg,tot_size_1st_msg,0)<0){
		printf("Error receiving first message\n");
		return -1;
	}

	if(its_for_me(first_msg,my_id)==1){
		id_requestor=get_id_requestor(first_msg);
		my_nonce=generate_nonce();
		nonce_other_side=get_nonce_other_side(first_msg);
		//Here I've to generate the key and then 
		session_key=generate_session_key(secret_len);
		
		//send <session_key,nonce_other_side> encrypted with the long term shared secret
		write(client_sock,generate_first_msg(id_requestor, my_id, my_nonce),tot_size_1st_msg);
		}else{
		printf("Error: the message it's not for me.\n");
		return -1;
		}

	printf("My nonce\t");
	prn_msg(my_nonce,2);
	printf("Nonce Client\t");
	prn_msg(nonce_other_side,2);
	printf("Session key\t");
	prn_msg(session_key, 2);

	free(id_requestor);
	free(nonce_other_side);
	free(my_nonce);
	return 0;

}
#endif
