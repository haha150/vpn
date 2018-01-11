//============================================================================
// Name        : sslUtils.cpp
// Description : This class is inspired by the openssl wiki page.
//============================================================================

#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <cstdio>
#include "sslUtils.h"
#include "commonUtils.h"
#include <openssl/err.h>
#include <iostream>
#include <openssl/conf.h>

BIO *bio_err = 0;
BIO *sbio;
unsigned char keys[48]; /* Store our key and iv in this array to send it over SSL */
unsigned char key[32]; /* Store the key in this array, 256 bit */
unsigned char iv[16]; /* Store the iv in this array, 128 bit */

/* This method will handle exits called by the program, when something goes wrong,
 * print it to the BIO and print a error message then exit the program */
int berr_exit(const char *string) {
	BIO_printf(bio_err, "%s\n", string);
	ERR_print_errors(bio_err);
	exit(0);
}

/* This method is used for certificates that are password protected, it will return the length
 * of the password that were used when the certificates were created, in this case secretpassword
 * is the password for both server and client */
int password_cb(char *buf,int num,
  int rwflag,void *userdata)
  {
	char *pass = "secretpassword";
    if(num<strlen(pass)+1)
      return(0);

    strcpy(buf,pass);
    return(strlen(pass));
  }

//=======================Implement the four functions below============================================

SSL *createSslObj(int role, int contChannel, char *certfile, char *keyfile, char *rootCApath ) {
	/* In this function, you handle
	 * 1) The SSL handshake between the server and the client.
	 * 2) Authentication
	 * 		a) Both the server and the client rejects if the presented certificate is not signed by the trusted CA.
	 * 		b) Client rejects if the the server's certificate does not contain a pre-defined string of your choice in the common name (CN) in the subject.
	 */
	SSL *ssl;

	SSL_CTX *ctx;

	/* The following lines will initialize and load every library and crypto algorithm that is required */
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
	EVP_add_cipher(EVP_aes_256_cbc());
	SSLeay_add_ssl_algorithms();

	/* This checks if we are server, otherwise we are client */
	if(role == 0) {
		printf("I am server\n");
		/* Create a new SSL context object, the blueprint. The supported protocols are SSLv2, SSLv3, TLSv1, TLSv1.1 and TLSv1.2
		 * with the SSLv23*/
		ctx = SSL_CTX_new(SSLv23_server_method());

		/* Configure how the context will verify the peer certificate that is received */
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

		/* Loads the trust certificate store for the given context, holds the root certificate */
		SSL_CTX_load_verify_locations(ctx, "/home/cdev/SSLCerts/CA/rootCA.pem", NULL);

		/* Loads the identity certificate which returns an error if it is < 0 */
		if(SSL_CTX_use_certificate_file(ctx,"/home/cdev/SSLCerts/srv.pem", SSL_FILETYPE_PEM) < 0) {
			berr_exit("Can’t read certificate file");
		}

		/* Since the loaded key might be password protected, this will set the action to authenticate the
		 * key with this password method */
		SSL_CTX_set_default_passwd_cb(ctx,password_cb);

		/* Loads the private key of the identity certificate, < 0 is an error */
		if(SSL_CTX_use_PrivateKey_file(ctx,"/home/cdev/SSLCerts/srv.key",SSL_FILETYPE_PEM) < 0) {
			berr_exit("Can’t read key file");
		}

		/* Check if the loaded public and private keys match, true or false is returned */
		if(!SSL_CTX_check_private_key(ctx)) {
			berr_exit("Can’t verify private key");
		}

		/* Finally load the trust certificate store for the given context */
		ssl = SSL_new(ctx);

		/* Wrap the TCP channel named contChannel with a buffered input/output */
		sbio = BIO_new_socket(contChannel, BIO_NOCLOSE);

		/* Define the BIO that this ssl object will read/write from/to, we use same for both */
		SSL_set_bio(ssl, sbio, sbio);

		/* Perform the SSL handshake. Accept will receive a new client that connects. */
		SSL_accept(ssl);

		/* Verify that the certificate is X509 and exists */
		if(SSL_get_verify_result(ssl) != X509_V_OK) {
			berr_exit("Certificate doesn't verify");
		}

		X509 *peer; /* Variable to store the peer certificate */
		char peer_CN[256]; /* Variable to store the peer common name */

		/* Get and save the peer certificate to the peer variable, this is the certificate that the client
		 * has sent to the server */
		peer = SSL_get_peer_certificate(ssl);

		/* Get the common name from the peer certificate */
		X509_NAME_get_text_by_NID(X509_get_subject_name(peer),NID_commonName, peer_CN, 256);

		/* Checks if the peer certificate common name has the known client common name,
		 * if not, kill the application */
		if(strcasecmp(peer_CN,"TP Client symeri@kth.se jimmyd@kth.se") != 0) {
			printf(peer_CN);
			berr_exit(peer_CN);
		}

		/* Get and save the peer certificate issuer name to the variable */
		char *peer_ISSUER = X509_NAME_oneline(X509_get_issuer_name(peer), NULL, 0);
		std::string issuer = peer_ISSUER; /* Downcasted to a string for comparison */

		/* Checks if the issuer of the peer certificate is signed by the root CA,
		 * if not, kill the application */
		if(issuer.find("TP CA symeri@kth.se jimmyd@kth.se") == std::string::npos) {
			printf("issuer %s", issuer);
			berr_exit(peer_ISSUER);
		}

		/* Free the peer resource */
		X509_free(peer);
	} else {
		printf("I am client\n");
		/* Create a new SSL context object, the blueprint. The supported protocols are SSLv2, SSLv3, TLSv1, TLSv1.1 and TLSv1.2
		* with the SSLv23*/
		ctx = SSL_CTX_new(SSLv23_client_method());

		/* Configure how the context will verify the peer certificate that is received */
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

		/* Loads the trust certificate store for the given context, holds the root certificate */
		SSL_CTX_load_verify_locations(ctx, "/home/cdev/SSLCerts/CA/rootCA.pem", NULL);

		/* Loads the identity certificate which returns an error if it is < 0 */
		if(SSL_CTX_use_certificate_file(ctx,"/home/cdev/SSLCerts/cli.pem", SSL_FILETYPE_PEM) < 0) {
			berr_exit("Can’t read certificate file");
		}

		/* Since the loaded key might be password protected, this will set the action to authenticate the
		* key with this password method */
		SSL_CTX_set_default_passwd_cb(ctx,password_cb);

		/* Loads the private key of the identity certificate, < 0 is an error */
		if(SSL_CTX_use_PrivateKey_file(ctx,"/home/cdev/SSLCerts/cli.key",SSL_FILETYPE_PEM) < 0) {
			berr_exit("Can’t read key file");
		}

		/* Check if the loaded public and private keys match, true or false is returned */
		if(!SSL_CTX_check_private_key(ctx)) {
			berr_exit("Can’t verify private key");
		}

		/* Finally load the trust certificate store for the given context */
		ssl = SSL_new(ctx);

		/* Wrap the TCP channel named contChannel with a buffered input/output */
		sbio = BIO_new_socket(contChannel, BIO_NOCLOSE);

		/* Define the BIO that this ssl object will read/write from/to, we use same for both */
		SSL_set_bio(ssl, sbio, sbio);

		/* Perform the SSL handshake. Connect will connect to the server. */
		SSL_connect(ssl);

		X509 *peer; /* Variable to store the peer certificate */
		char peer_CN[256]; /* Variable to store the peer common name */

		/* Verify that the certificate is X509 and exists */
		if(SSL_get_verify_result(ssl) != X509_V_OK) {
			berr_exit("Certificate doesn't verify");
		}

		/* Get and save the peer certificate to the peer variable, this is the certificate that the server
		* has sent to the client */
		peer = SSL_get_peer_certificate(ssl);

		/* Get the common name from the peer certificate */
		X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_commonName, peer_CN, 256);

		/* Checks if the peer certificate common name has the known client common name,
		* if not, kill the application */
		if(strcasecmp(peer_CN,"TP Server symeri@kth.se jimmyd@kth.se") != 0) {
			printf("cn %s", peer_CN);
			berr_exit(peer_CN);
		}

		/* Get and save the peer certificate issuer name to the variable */
		char *peer_ISSUER = X509_NAME_oneline(X509_get_issuer_name(peer), NULL, 0);
		std::string issuer = peer_ISSUER; /* Downcasted to a string for comparison */

		/* Checks if the issuer of the peer certificate is signed by the root CA,
		* if not, kill the application */
		if(issuer.find("TP CA symeri@kth.se jimmyd@kth.se") == std::string::npos) {
			printf("issuer %s", issuer);
			berr_exit(peer_ISSUER);
		}

		/* Free the peer resource */
		X509_free(peer);
	}
	return ssl;
}

void dataChannelKeyExchange(int role, SSL *ssl) {
	/* In this function, you handle
	 * 1) The generation of the key and the IV that is needed to symmetrically encrypt/decrypt the IP datagrams over UDP (data channel).
	 * 2) The exchange of the symmetric key and the IV over the control channel secured by the SSL object.
	 */
	/* Since we are about to random some keys, The pseudo-random number generator is initialized using the argument passed as seed  */
	srand (time(NULL));

	if(role == 0) { /* If we are server */
		/* This first loop will random 32 numbers from 1 to 256,
		 * they will represent the key */
		int i;
		for(i = 0; i < 32; i++) {
			key[i] += rand() % 256 + 1;
		}
		/* This second loop will random 16 numbers from 1 to 256,
		 * they will represent the iv */
		int j;
		for(j = 0; j < 16; j++) {
			iv[j] += rand() % 256 + 1;
		}
		/* The following third and fourth loops will store both the key and iv into a larger array so
		 * that we can send them both once to the client */
		int c;
		for(c = 0; c < 32; c++) {
			keys[c] = key[c];
		}
		int d;
		int e = 0;
		for(d = 32; d < 48; d++) {
			keys[d] = iv[e];
			e++;
		}

		/* With SSL write we write data of length n to the secure channel,
		 * we are sending the keys array which has stored the key and iv  */
		SSL_write(ssl, keys, 48);
	} else {
		/* With SSL read we read n, which is 48 in this case,
		 * bytes into the buffer, which is keys, and save the amount of bytes into x,
		 * x should be equal to n */
		int x = SSL_read(ssl, keys, 48);
		if(x != 48) {
			berr_exit("There is a problem with reading the random number\n");
		}
		/* The following two loops simply unwraps the key and iv from the keys array that we read */
		int i;
		for(i = 0; i < 32; i++) {
			key[i] = keys[i];
		}
		int j;
		int e = 0;
		for(j = 32; j < 48; j++) {
			iv[e] = keys[j];
			e++;
		}
	}
}

/* This method handle errors regarding encrypt and decrypt,
 * if something goes wrong, prints an error and exits the application */
void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

/* This method handle errors regarding encrypt and decrypt,
 * if something goes wrong, prints an error.
 * It is here because when an initial message is sent the decrypt might fail */
void handleErrorsForInitMsg(void)
{
  ERR_print_errors_fp(stderr);
}

int encrypt(unsigned char *plainText, int plainTextLen,
		unsigned char *cipherText) {
	/* In this function, you store the symmetrically encrypted form of the IP datagram at *plainText, into the memory at *cipherText.
	 * The memcpy below directly copies *plainText into *cipherText, therefore the tunnel works unencrypted. It is there for you to
	 * test if the tunnel works initially, so remove that line once you start implementing this function.
	 */

	int len = 0; /* The length variable we store data length that we have read */

	int ciphertext_len = 0; /* The total length of the encrypted data */

	EVP_CIPHER_CTX *ctx;

	/* Initialize and create a object of the EVP cipher context, exit if it fails */
	if(!(ctx = EVP_CIPHER_CTX_new())) {
		handleErrors();
	}

	/* Sets up cipher context ctx for encryption with cipher type EVP_aes_256_cbc, using key and iv.
	 * Key is the symmetric key to use and iv is the IV to use */
	if(!EVP_EncryptInit_ex(ctx,EVP_aes_256_cbc(),NULL,key,iv)) {
		handleErrors();
	}

	/* Encrypts plainTextLen bytes from the buffer plainText and writes the encrypted version to cipherText.
	 * The actual number of bytes written is placed in the len variable */
	if(!EVP_EncryptUpdate(ctx, cipherText, &len, plainText, plainTextLen)) {
		handleErrors();
	}
	ciphertext_len = len; /* Save the number of bytes written to the total length */

	/* Encrypts the "final" data, starting from where we left of above, that is any data that remains in a partial block .
	 * The number of bytes written is placed in len */
	if(!EVP_EncryptFinal_ex(ctx, cipherText + len, &len)) {
		handleErrors();
	}
	ciphertext_len += len; /* Append the remaining number of bytes written to the total length */

	/* Free the context resource */
	EVP_CIPHER_CTX_free(ctx);

	/* Finally return the total length of the encrypted data */
	return ciphertext_len;
}

int decrypt(unsigned char *cipherText, int cipherTextLen,
		unsigned char *plainText) {
	/* In this function, you symmetrically decrypt the data at *cipherText and store the output IP datagram at *plainText.
	 * The memcpy below directly copies *cipherText into *plainText, therefore the tunnel works unencrypted. It is there for you to
	 * test if the tunnel works initially, so remove that line once you start implementing this function.
	 */

	int len = 0; /* The length variable we store data length that we have read */

	int plaintext_len = 0; /* The total length of the encrypted data */

	EVP_CIPHER_CTX *ctx;

	/* Initialize and create a object of the EVP cipher context, exit if it fails */
	if(!(ctx = EVP_CIPHER_CTX_new())) {
		handleErrors();
	}

	/* Sets up cipher context ctx for decryption with cipher type EVP_aes_256_cbc, using key and iv.
	* Key is the symmetric key to use and iv is the IV to use */
	if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
		handleErrors();
	}

	/* Decrypts cipherTextLen bytes from the buffer cipherText and writes the decrypted version to plainText.
	* The actual number of bytes written is placed in the len variable */
	if(!EVP_DecryptUpdate(ctx, plainText, &len, cipherText, cipherTextLen)) {
		handleErrors();
	}
	plaintext_len = len; /* Save the number of bytes written to the total length */

	/* Decrypts the "final" data, starting from where we left of above, that is any data that remains in a partial block .
	* The number of bytes written is placed in len.
	* Note that this might fail when sending a initial message so it will not exit the application when
	* errors occur. */
	if(!EVP_DecryptFinal_ex(ctx, plainText + len, &len)) {
		handleErrorsForInitMsg();
	}
	plaintext_len += len; /* Append the remaining number of bytes written to the total length */

	/* Free the context resource */
	EVP_CIPHER_CTX_free(ctx);

	/* Finally return the total length of the decrypted data */
	return plaintext_len;
}

