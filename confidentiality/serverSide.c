#include<stdio.h>
#include<string.h>    //strlen
#include<sys/socket.h>
#include<arpa/inet.h> //inet_addr
#include<unistd.h>    //write
#include<openssl/bn.h>
#include<openssl/dh.h>
#include"enc_lib.h"

#define CL_MSG_SIZE 1000
#define PORT_NUMBER 8888
#define KEY_LENGHT 512

int main(int argc , char *argv[]){
	int socket_desc , client_sock , c , read_size;
	struct sockaddr_in server , client;
	unsigned char *client_message=calloc(CL_MSG_SIZE,sizeof(char));
	int socket_dest=0;

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
    	puts("bind done");
     //...qua dovrebbe diventare una funzione, però è un bordello perchè ci stanno puntatori ovunque. Da fare a tempo perso
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
	while( (read_size = recv(client_sock , client_message , CL_MSG_SIZE, 0)) > 0 ){
	int key_len=EVP_CIPHER_key_length(EVP_des_ecb());
	int block_size=EVP_CIPHER_block_size(EVP_des_ecb());
	unsigned char *key=calloc(key_len, sizeof(unsigned char));
	set_key_zero(key,key_len);

	//I'm going to decrypt client message
	EVP_CIPHER_CTX* ctx=enc_initialization(key);
	printf("size of cipher text:%d\n",(int)sizeof(client_message));
	unsigned char* plain_text=dec_msg(client_message,ctx, key, block_size,sizeof(client_message));
	del_padding(plain_text);
	printf("I've received %s from the client\n",plain_text);
	prn_msg((const char*)plain_text, 2);
	memset(client_message,0,sizeof(CL_MSG_SIZE));
    }
     
    if(read_size == 0){
        puts("Client disconnected");
        fflush(stdout);
    }
    else if(read_size == -1)       perror("recv failed");
    
     
    return 0;
}
