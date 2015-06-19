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
int send_enc_msg(char* msg, int sock){
	//I choose the encryption type, key length and randomize it. 
	int res=-1;
	int cipher_size=0;
	int pippo=0;
	int key_len=EVP_CIPHER_key_length(DES_ECB);
	unsigned char *key=calloc(key_len, sizeof(unsigned char));
	set_key_zero(key,key_len);//I assume that this key is know by the other side, i.e. the server
	int block_size=EVP_CIPHER_block_size(DES_ECB);
	unsigned char* cipher_text=NULL;
	unsigned char * tmp=calloc(8, sizeof(unsigned char*));
	unsigned char* enc_cipher_size=NULL;

	printf("Enter message:");
	fgets(msg,DIM_CHAR_MSG,stdin);
	
	//RAND_bytes(key,key_len);//Actually the key is random generated
	//Message encrypted to send to the server. After encryption I know how much big is the cipher text
	cipher_text=enc_msg(msg, block_size, key, key_len, &cipher_size);
	sprintf((char*)tmp, "%d", cipher_size);

	enc_cipher_size=enc_msg(tmp, block_size, key, key_len, &pippo);//Encrypt the size of cipher text in order to far sapere al server quanto allocare

	printf("Enc_message\n");	
	prn_enc_msg(enc_cipher_size, pippo);	
	//I have to encrypt the size of encypted message. To fix
	if(send(sock, &cipher_size, sizeof(int), 0) >0) res=send(sock , cipher_text ,cipher_size, 0);//If the send of cipher size goes ok, then send the cipher text
	free(cipher_text);
	free(key);
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
