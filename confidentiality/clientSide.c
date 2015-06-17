#include<stdio.h> //printf
#include<string.h>    //strlen
#include<sys/socket.h>    //socket
#include<arpa/inet.h> //inet_addr
#include<openssl/bn.h>
#include<openssl/dh.h>
#include<unistd.h>
#include"enc_lib.h"

#define KEY_LENGHT 512
#define DIM_CHAR_MSG 500
#define PORT_NUMBER 8888

//Send an input message in clear (Not advisable to use)
int send_msg_clr(char* message, int sock){
	printf("Enter message:");
	fgets(message,DIM_CHAR_MSG,stdin);	
        //Send some data in clear
        return send(sock , message ,DIM_CHAR_MSG, 0);
}

int send_enc_msg(char* msg, int sock){
	printf("Enter message:");
	fgets(msg,DIM_CHAR_MSG,stdin);

	//I choose the encryption type, key length and randomize it. 
	int key_len=EVP_CIPHER_key_length(EVP_des_ecb());
	int block_size=EVP_CIPHER_block_size(EVP_des_ecb());
	unsigned char *key=calloc(key_len, sizeof(unsigned char));
	//RAND_bytes(key,key_len);//Actually the key is random generated 
	set_key_zero(key,key_len);//I assume that this key is know by the other side, i.e. the server
		

	//Ctx will be inizializated
	EVP_CIPHER_CTX* ctx=enc_initialization(key);
	int cipher_size=0;
	unsigned char* cipher_text=enc_msg(msg, block_size, ctx, key, key_len, &cipher_size);//Message encrypted to send to the server

        //Send some data in clear
	int res=send(sock , cipher_text ,cipher_size, 0);
	free(cipher_text);
	free(key);
	free(ctx);
        return res;
}

//Creation of a socket and connection to a local host server
int create_socket_and_connect(){

	struct sockaddr_in server;
	const char* LOCAL_HOST="127.0.0.1";
	int sock = socket(AF_INET , SOCK_STREAM , 0);
	int connection;
	if (sock == -1){     
		printf("Could not create socket");
		return -1;    
		}

	puts("Socket created correctly");
     
	server.sin_addr.s_addr = inet_addr(LOCAL_HOST);
	server.sin_family = AF_INET;
	server.sin_port = htons( PORT_NUMBER );

 	connection=connect(sock , (struct sockaddr*)&server , sizeof(server));
	    //Connect to remote server
	printf("connection:%d\n",connection);
	if(connection<0){
		printf("Error connection\n");	
		return -1;
		}
	else{ 
		printf("Connection done\n");
		return sock;	
		}
}


int main(int argc , char *argv[])
{
	char* message=calloc(DIM_CHAR_MSG,sizeof(char));
	int sock=create_socket_and_connect();

    if(sock<0)	return -1;

    while(1)//keep communicating with server
    {

	if(send_enc_msg(message, sock)<0){
		puts("Send failed");
		return -1;
		}
    }
     	//Free stuff
    	close(sock);
	free(message);
    return 0;
}
