#include<stdio.h> //printf
#include<string.h>    //strlen
#include<sys/socket.h>    //socket
#include<arpa/inet.h> //inet_addr
#include<openssl/bn.h>
#include<openssl/dh.h>
#include<unistd.h>
#include"enc_lib.h"

#define KEY_LENGHT 512
#define DIM_CHAR_MSG 1000
#define DIM_SER_RPL_MSG 1000
#define PORT_NUMBER 8888

//Send the message in clear (Not advisable to use)
int send_msg_clr(char* message, int sock){
	printf("Enter message:");
	fgets(message,DIM_CHAR_MSG,stdin);	
        //Send some data in clear
        return send(sock , "Ciao sono giuanninedda" ,DIM_CHAR_MSG, 0);
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
	char* server_reply=calloc(DIM_CHAR_MSG,sizeof(char));
	int sock=create_socket_and_connect();
	EVP_CIPHER_CTX* ctx=enc_initialization(0);
    if(sock<0)	return -1;

    while(1)//keep communicating with server
    {
	if(send_msg_clr(message, sock)<0){
		puts("Send failed");
		return -1;
		}
	break;
    }
     	//Free stuff
    	close(sock);
	free(message);
	free(server_reply);
    return 0;
}
