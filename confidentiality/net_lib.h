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
#define NET_LIB 73 


#define PORT_NUMBER 8888 //Arbitrary port number
#define DIM_CHAR_MSG 100 //Max input size message
#define MEMSET_YES 1 //After encryption\decryption the cipher\plain text must be clear after its send
#define MEMSET_NO 0

//Send a generic message msg, with size size_msg.
int send_msg(int sock, void* msg, int size_msg, int memset_yes){
	int res=-1;
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
#endif
