#include"enc_lib.h"
#include"net_lib.h"
#include"util_lib.h"

#define DEFAULT_ID_CLIENT "9999"
#define DEFAULT_ID_SERVER "1234"
#define DIM_CHAR_MSG 100

int main(int argc , char *argv[])
{
	int tot_size_1st_msg=2*ID_SIZE+NONCE_SIZE+1;
	unsigned char* my_id=calloc(ID_SIZE,sizeof(unsigned char));
	unsigned char* id_server=calloc(ID_SIZE,sizeof(unsigned char));
	unsigned char* nonce_other_side=calloc(NONCE_SIZE,sizeof(unsigned char));
	//unsigned char *cipher_text=NULL;
	//int cipher_size=0;

	switch (argc){
	case 1:
		my_id=(unsigned char*)DEFAULT_ID_CLIENT;//Default
		id_server=(unsigned char*)DEFAULT_ID_SERVER;//Default
		break;

	case 2:
		if((int)strlen((const char*)argv[1])!=ID_SIZE){
				printf("The id length must be %d\n",ID_SIZE);
				return -1;
				}
		my_id=(unsigned char*)argv[1];
		id_server=(unsigned char*)DEFAULT_ID_SERVER;
		break;

	case 3://To do: make this control: my_id and id_server must not be equal
		if(((int)strlen((const char*)argv[1])!=ID_SIZE) & ((int)strlen((const char*)argv[2])!=ID_SIZE)){
			printf("The id length must be %d\n",ID_SIZE);
			return -1;
			}
		my_id=(unsigned char*)argv[1];
		id_server=(unsigned char*)argv[2];
		break;
	}

	unsigned char* my_nonce=generate_nonce();
	unsigned char *first_msg=generate_first_msg(my_id, id_server,my_nonce);
	int secret_len=EVP_CIPHER_key_length(AES_256_CBC);
	printf("Secret_len in byte=%d\n",secret_len);
//The secret has to be read from the file not hard code way
	unsigned char *secret=calloc(secret_len, sizeof(unsigned char));
	set_secret_zero(secret,secret_len);//I assume that this secret is know by the other side, i.e. the server
	//int block_size=EVP_CIPHER_block_size(AES_256_CBC);

	int sock=create_socket_and_connect();
	if(sock<0)	return -1;
		if(send(sock, first_msg,tot_size_1st_msg,MEMSET_YES)<0){
			printf("Error sending 1st message\n");
			return -1;
		}

		if(recv(sock, first_msg,tot_size_1st_msg,0)<0){
			printf("Error receiving message from the server\n");
			return -1;
		}	
		nonce_other_side=get_nonce_other_side(first_msg);
		printf("My nonce\t");
		prn_msg(my_nonce,2);
		printf("Nonce server\t");
		prn_msg(nonce_other_side,2);
		close(sock);
	//Free stuff
	
	free(first_msg);
/*At least one of these free gives problems. Find which and why
	free(id_server);
	free(nonce_other_side);
	free(my_nonce);
	free(secret);
	*/
	return 0;
}
