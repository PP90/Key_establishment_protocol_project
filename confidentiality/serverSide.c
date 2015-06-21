#include<stdio.h>
#include<string.h>    //strlen
#include<sys/socket.h>
#include<arpa/inet.h> //inet_addr
#include<unistd.h>    //write
#include<openssl/bn.h>
#include<openssl/dh.h>
#include"enc_lib.h"

#define PORT_NUMBER 8888

int main(int argc , char *argv[]){
	int socket_desc , client_sock , c , read_size;
	struct sockaddr_in server , client;
	unsigned char *client_message=calloc(1,sizeof(unsigned char));;
	int socket_dest=0;

	int cipher_size=0;
	int key_len=EVP_CIPHER_key_length(DES_ECB);
	int block_size=EVP_CIPHER_block_size(DES_ECB);

	unsigned char *key=calloc(key_len, sizeof(unsigned char));
	unsigned char* cipher_size_encrypted=calloc(8,sizeof(unsigned char));
	unsigned char* cipher_size_pt=calloc(8,sizeof(unsigned char));
	unsigned char* plain_text=NULL;
	set_key_zero(key,key_len);

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
//	socket_dest=create_socket_and_listen();
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
     
    //Receive a message from client
	while(recv(client_sock, cipher_size_encrypted,8, 0)>0){
		cipher_size_pt=dec_msg(cipher_size_encrypted, block_size, 8, key);
		cipher_size=atoi((const char*)cipher_size_pt);
		client_message=realloc(client_message, cipher_size);//Realloc the new space for the new message incoming
		
	if((read_size =recv(client_sock, client_message, cipher_size, 0))>0){
		plain_text=dec_msg(client_message, block_size, cipher_size, key);//I'm going to decrypt client message
		printf("I've received %s from the client\n",plain_text);
		memset(client_message,0,cipher_size);//I clean the old received cipher_text
		memset(plain_text,0,(int)strlen((const char*)plain_text));//I clean the old plain_text
	}else{
		printf("Error receiving encrypted message\n");
		return -1;			
		}
 
	if(read_size==0 || read_size==1){		
		if(read_size == -1)perror("recv failed\n");
		
		if(read_size == 0){
			puts("Client disconnected\n");
			fflush(stdout);
			}
		}
			
	}
		free(cipher_size_pt);
		free(plain_text);
		free(client_message);
		free(key);
    return 0;
}
