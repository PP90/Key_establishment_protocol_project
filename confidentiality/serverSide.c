#include"enc_lib.h"
#include"net_lib.h"
#include"util_lib.h"
#include"hash_lib.h"

#ifndef SER_SRC 
#define SER_SRC 4332

#define DEFAULT_ID_SERVER "1234"//The default id server


int main(int argc , char *argv[]){

	unsigned char* my_id=(unsigned char*)DEFAULT_ID_SERVER;
	unsigned char *session_key=NULL;

	int secret_size;
	int key_size;
	int block_size;
	enc_inizialization(&secret_size, &key_size, &block_size);
	

	//Check on command line inputs
	//In case of second argument is 2,then set the second value as a ID server
	if(argc==2) my_id=(unsigned char*)argv[1];

	int socket_desc , client_sock , c;
	struct sockaddr_in server , client;
	int socket_dest=0;

	//The secret actually must be retrived from an ecrypted file
	unsigned char *secret=calloc(secret_size, sizeof(unsigned char));
	secret=retrieve_secret(NULL,secret_size);
    
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
        	perror("bind failed. Error");
        	return 1;
    	}
    	puts("Bind done");


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

session_key=protocol_server(client_sock, my_id,secret, secret_size, block_size,key_size);

	printf("\nStart Session\n");

	session_server(client_sock, block_size, session_key, key_size);
	return 0;

}
#endif
