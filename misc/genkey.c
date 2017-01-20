/*
 *  CryptoUtils.c
 */

#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

#define passphrase ((unsigned char *)"qwerty1234")

#define PUBKEYFILE "pubkey.pem"
#define PRVKEYFILE "prvkey.pem"

int generateKeys(int keylen);

int generateKeys(int keylen) {

    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned long err_code;
    FILE *fd_pubkey;
    FILE *fd_privkey;
    FILE *fd_md;
    FILE *fd_sig;
    int rc;

    if (keylen != 1024 && keylen != 2048 && keylen != 4096) {
        fprintf(stderr, "Error: Invalid key length:\n");
        return 1;
    }
        
    err_code = 0;
    pkey = NULL;
    fd_pubkey = fd_privkey = fd_md = fd_sig = NULL;
    fd_pubkey = fd_md = fd_sig = NULL;
    rc = 0;
    
    /*** Generate keypair ***/
    
    /* Prepare the keygen context */
    if (!(ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL))) goto cleanall;
    if (EVP_PKEY_keygen_init(ctx) <= 0) goto cleanall;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keylen) <= 0) goto cleanall;
    
    /* Generate keypair */
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) goto cleanall;
    
    /* Write keypair to file */
    
    if (!(fd_pubkey = fopen(PUBKEYFILE, "w"))) goto cleanall;
    if (!PEM_write_PUBKEY(fd_pubkey, pkey)) goto cleanall;
    if (!(fd_privkey = fopen(PRVKEYFILE, "w"))) goto cleanall;
    if (!PEM_write_PrivateKey(fd_privkey, pkey, NULL, NULL, 0, NULL, NULL)) goto cleanall;

cleanall:
    
    if(err_code) {
        fprintf(stderr, "ERROR");
        rc = 1;
    }
    
    if (fd_pubkey) { fclose(fd_pubkey); fd_pubkey = NULL; }
    if (fd_privkey) { fclose(fd_privkey); fd_privkey = NULL; }
    if (ctx) { EVP_PKEY_CTX_free(ctx); ctx = NULL; }
        
    return rc;
}

int main(int argc, char *argv[]) {

  RSA *key;
  FILE *fd;
  unsigned char *out, hash[21];
  char *prefix, fingerprint[41];
  int n, i, err_code;

    if (argc != 2 || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
        fprintf(stdout, "Usage: ./%s <prefix>\n", argv[0]);
	return 0;
    }

    prefix = argv[1];
    
    /* Initialization */
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    do {

      if (generateKeys(1024)) {
        fprintf(stderr, "Error generating keypair.\n");
        return 1;
      }

      if(!(fd = fopen(PUBKEYFILE, "r"))) {
	fprintf(stderr, "Error opening key file.\n");
	return 1;
      }

      if(!(key = PEM_read_RSA_PUBKEY(fd, NULL, NULL, NULL))) {
	err_code = ERR_get_error();
	fprintf(stderr, "Error loading public key: %s\n", ERR_error_string(err_code, NULL));      
	return 1;
      }

      out = NULL;
      if((n = i2d_RSAPublicKey(key, &out)) < 0) {
	fprintf(stderr, "Error: could not encode RSA public key.\n");
	return 1;
      }

      memset(fingerprint, 0, 41);
      memset(hash, 0, 21);

      if(!SHA1(out, n, hash)) {
	fprintf(stderr, "Error calculating the hash...\n");
	return 1;
      }     

      for (i=0; i<20; i++) {
	sprintf(&fingerprint[i*2], "%02X", hash[i]);
      }

      fprintf(stdout, "Obtained fingerprint: %s\n", fingerprint);

    } while (strncmp(prefix, fingerprint, strlen(prefix)));

    CRYPTO_cleanup_all_ex_data();
    EVP_cleanup();

    return 0;

}

