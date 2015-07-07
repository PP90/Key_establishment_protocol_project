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

//Function that sends:
// The size of a message and the the message itself. It makes this in order to inform the server for reallocate correctly the buffer.
int send_msg(int sock, void* msg, int size_msg, int memset_yes){
	int res=-1;
	if(msg==NULL){
		fprintf(stderr,"Error: The message is NULL\n");
		return res;
	}
	if(size_msg==0){
		fprintf(stderr,"Error: The message has size 0\n");
		return res;
	}	

	if((memset_yes!=MEMSET_YES) & (memset_yes!=MEMSET_NO)){
		fprintf(stderr,"Error: mem_set_yes must be %d or %d\n",MEMSET_NO, MEMSET_YES);
		return res;
	}

	if((res=send(sock, msg, size_msg, 0)) >0){//I made the memset only if the send of the message goes ok
		if(memset_yes==MEMSET_YES)	memset(msg,0,size_msg);
	}else	fprintf(stderr,"Error sending message\n");

	return res;
}

//Creation of a socket and connection to the local host server
int create_socket_and_connect(){

	struct sockaddr_in server;
	const char* LOCAL_HOST="127.0.0.1";
	int sock = socket(AF_INET , SOCK_STREAM , 0);
	int connection=0;
	if (sock == -1){     
		fprintf(stderr,"Could not create socket");
		return -1;    
		}

	puts("Socket created correctly");
     
	server.sin_addr.s_addr = inet_addr(LOCAL_HOST);
	server.sin_family = AF_INET;
	server.sin_port = htons( PORT_NUMBER );
	connection=connect(sock ,(struct sockaddr*)&server , sizeof(server));
	if(connection<0){
		fprintf(stderr,"Error connection\n");	
		return -1;
		}
	else{ 
		fprintf(stderr,"Connection done\n");
		return sock;	
		}

	return connection;

}
#endif
