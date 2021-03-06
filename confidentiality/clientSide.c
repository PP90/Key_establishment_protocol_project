#include"enc_lib.h"
#include"net_lib.h"
#include"util_lib.h"
#include"hash_lib.h"
#include"session.h"

#define DEFAULT_ID_CLIENT "9999"//The default value of client ID
#define DEFAULT_ID_SERVER "1234"//The default value of server ID


int main(int argc , char *argv[])
{
	int secret_size;
	int key_size;
	int block_size;

	enc_inizialization(&secret_size, &key_size, &block_size);
    
	unsigned char* my_id=calloc(ID_SIZE,sizeof(unsigned char));
	unsigned char* id_server=calloc(ID_SIZE,sizeof(unsigned char));
	unsigned char* session_key=NULL;

	switch (argc){//The command line could have from 1 to 3 arguments
	case 1:
		my_id=(unsigned char*)DEFAULT_ID_CLIENT;//Default
		id_server=(unsigned char*)DEFAULT_ID_SERVER;//Default
		break;

	case 2:
		if((int)strlen((const char*)argv[1])!=ID_SIZE){
				fprintf(stderr, "The id length must be %d\n",ID_SIZE);
				return -1;
				}
		my_id=(unsigned char*)argv[1];
		id_server=(unsigned char*)DEFAULT_ID_SERVER;
		break;

	case 3://To do: make this control: my_id and id_server must not be equal
		if(((int)strlen((const char*)argv[1])!=ID_SIZE) & ((int)strlen((const char*)argv[2])!=ID_SIZE)){
			fprintf(stderr,"The id length must be %d\n",ID_SIZE);
			return -1;
			}
		my_id=(unsigned char*)argv[1];
		id_server=(unsigned char*)argv[2];
		break;
	}

//The secret has to be read from the file not hard code way
	unsigned char *secret=calloc(secret_size, sizeof(unsigned char));
    secret=retrieve_secret(NULL,secret_size);

	int sock=create_socket_and_connect();
	if(sock<0)	return -1;
	//START PROTOCOL
	session_key=protocol_client(sock,my_id,id_server,secret, secret_size,block_size,key_size);
	fprintf(stderr,"\nStart Session\n");
	session_client(sock, block_size, session_key, key_size);
	free(session_key);
	close(sock);
	return 0;
}
