#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

int decryptf(FILE * fp)
{
       
	    char * encrypted;
        encrypted=(char *)malloc(encrylen * sizeof(char));
        fread(encrypted,encrylen,1,fp);
        fclose(fp);

        char decrypted[1024];

        const char* priv_key="private.pem";

    	FILE* priv_fp=fopen(priv_key,"r");
    	if(priv_fp==NULL){
        	printf("failed to open priv_key file %s!\n", priv_key);
        	return -1;
    	}

    	// read private key from private key file
    	RSA *rsa2 = PEM_read_RSAPrivateKey(priv_fp, NULL, NULL, NULL);
    	if(rsa2==NULL){
        	printf("unable to read private key!\n");
        	return -1; 
    	}
    
    	// use private key to decrypt encrypted data
    	int decrylen=RSA_private_decrypt(encrylen, encrypted, decrypted, rsa2, RSA_PKCS1_PADDING);
    	if(decrylen==-1){
        	printf("failed to decrypt!\n");
        	return -1;
    	}

    	fclose(priv_fp);
        
        printf("in decryptf func, decrylen is:\n%d\n",decrylen);

    	// output decrypted plain text
        printf("in decryptf func, decrypted string is \n%s\n",decrypted);

        // output decrypted data to a new file
        FILE* ffp=fopen("a_decrypted","w");
        if(ffp){
             fwrite(decrypted,decrylen,1,ffp);
             fclose(ffp);
        }
}

int main()
{
        FILE * decry_fp;

        decry_fp=fopen("midata","r");
        decryptf(decry_fp);
        return 1;
}

