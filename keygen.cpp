// Program that generates an RSA public key/private key pair and saves them to files.  
#include <stdlib.h>
#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>

int main (void)
{
	// generates public and private keys and saves them to a file
	RSA *theKey = RSA_generate_key(512, 3, NULL, NULL);

	printf("KEY SIZE: %d\n", RSA_size(theKey));
	
	FILE * privateKeyOut =fopen("privkey.pem", "w");
	FILE * publicKeyOut = fopen("pubkey.pem", "w");

	PEM_write_RSAPrivateKey(privateKeyOut, theKey, NULL, NULL, 0, NULL, NULL);
	PEM_write_RSAPublicKey(publicKeyOut, theKey);
	
	fclose(privateKeyOut);
	fclose(publicKeyOut);

	publicKeyOut = fopen("pubkey.pem", "r");
	privateKeyOut =fopen("privkey.pem", "r");
	
	//test if key can be read back
	RSA *Read_test = RSA_new();
	PEM_read_RSAPrivateKey(privateKeyOut, &Read_test, NULL, NULL); 
	PEM_read_RSAPublicKey(publicKeyOut, &Read_test, NULL, NULL);

	return 0;
}