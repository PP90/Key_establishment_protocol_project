#include<stdio.h> 
#include<string.h>    
#include<sys/socket.h>    
#include<arpa/inet.h> 
#include<openssl/bn.h>
#include<openssl/dh.h>
#include<unistd.h>
#include"enc_lib.h"

#define PORT_NUMBER 8888
#define DIM_CHAR_MSG 100



//Encrypt the message and then send it
int send_enc_msg(int sock){
	
	unsigned char* cipher_text=NULL;
	unsigned char* msg=calloc(DIM_CHAR_MSG,sizeof(unsigned char));
	unsigned char* cipher_len_to_encrypt=calloc(3,sizeof(unsigned char));
	unsigned char* cipher_len_encrypted=calloc(8,sizeof(unsigned char));
	int cipher_size=0;
	int size_of_encrypted_size=0;
	int res=0;
	
	printf("Enter message:");
	fgets((char*)msg,DIM_CHAR_MSG,stdin);
	cipher_text=enc_msg_with_DES_EBC((unsigned char*)msg, &cipher_size);	
	
	sprintf((char*)cipher_len_to_encrypt,"%d", cipher_size);
		
	cipher_len_encrypted=enc_msg_with_DES_EBC((unsigned char*)cipher_len_to_encrypt, &size_of_encrypted_size);
	prn_enc_msg(cipher_len_encrypted,8);
	if(send(sock,cipher_len_encrypted, size_of_encrypted_size, 0) >0){
		res=send(sock , cipher_text ,cipher_size, 0);//If the send of cipher size goes ok, then send the cipher text
		}
	memset(msg,0,cipher_size);
	free(msg);
	memset(cipher_text,0,cipher_size);
	free(cipher_text);
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
	int sock=create_socket_and_connect();
	
    if(sock<0)	return -1;

    while(1)//keep communicating with server
    {

	if(send_enc_msg(sock)<0){
		puts("Send failed");
		return -1;
		}
    }
     	//Free stuff
    	close(sock);
    return 0;
}
