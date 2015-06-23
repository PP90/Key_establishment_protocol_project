#include<stdio.h> //printf
#include<string.h>    //strlen
#include<sys/socket.h>    //socket
#include<arpa/inet.h> //inet_addr
#include<openssl/bn.h>
#include<openssl/dh.h>
#include<unistd.h>
#include<openssl/evp.h>
#include<openssl/rand.h>


#ifndef NET_LIB
#define NET_LIB 73 //THE CHUCK NORRIS OF THE NUMBER


#define PORT_NUMBER 8888
#define DIM_CHAR_MSG 100
#define MEMSET_YES 1
#define MEMSET_NO 0

//Encrypt the message , send it's encrypted size and then send the encrypted message. This is done because the server has to know how much space must be alloacated.

int send_msg(int sock, void* msg, int size_msg, int memset_yes){
	int res=-1;
	printf("size_msg:%d\n",size_msg);
	if(msg==NULL){
		printf("Error: The message is NULL\n");
		return res;
	}

	if(size_msg==0){
		printf("Error: The message has size 0\n");
		return res;
	}	

	if((memset_yes!=MEMSET_YES) & (memset_yes!=MEMSET_NO)){
		printf("Error: mem_set_yes must be %d or %d\n",MEMSET_NO, MEMSET_YES);
		return res;
	}

	if((res=send(sock, msg, size_msg, 0)) >0){
		if(memset_yes==MEMSET_YES)	memset(msg,0,size_msg);
	}else	printf("Error sending message\n");

	return res;
}

//Creation of a socket and connection to the local host server
int create_socket_and_connect(){

	struct sockaddr_in server;
	const char* LOCAL_HOST="127.0.0.1";
	int sock = socket(AF_INET , SOCK_STREAM , 0);
	int connection=0;
	if (sock == -1){     
		printf("Could not create socket");
		return -1;    
		}

	puts("Socket created correctly");
     
	server.sin_addr.s_addr = inet_addr(LOCAL_HOST);
	server.sin_family = AF_INET;
	server.sin_port = htons( PORT_NUMBER );
	connection=connect(sock ,(struct sockaddr*)&server , sizeof(server));
	if(connection<0){
		printf("Error connection\n");	
		return -1;
		}
	else{ 
		printf("Connection done\n");
		return sock;	
		}

	return connection;

}

/*
//Receive and decrypt the message. To split in two simplest functions
unsigned char* receive_msg(int client_sock, unsigned char* client_msg, int block_size, unsigned char* key, int cipher_size){
	int read_size=-1;
	unsigned char* plain_text=NULL;
	if((read_size =recv(client_sock, client_msg, cipher_size, 0))>0){
		plain_text=dec_msg(client_msg, block_size, cipher_size, key);//I'm going to decrypt client message
		printf("I've received %s from the client\n",plain_text);
		memset(client_msg,0,cipher_size);//I clean the old received cipher_text
		memset(plain_text,0,(int)strlen((const char*)plain_text));//I clean the old plain_text
	}else{
		printf("Error receiving encrypted message\n");
		return NULL;			
		}
 
	if(read_size==0 || read_size==1){		
		if(read_size == -1)perror("recv failed\n");
		
		if(read_size == 0){
			puts("Client disconnected\n");
			fflush(stdout);
			}
	}
	free(plain_text);
	return plain_text;
}
*/
#endif
