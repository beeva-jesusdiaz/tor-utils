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

int main(int argc, char *argv[]) {

  RSA *key;
  FILE *fd;
  unsigned char *out, hash[21];
  char fingerprint[41];
  int n, i, err_code;

    if (argc != 2 || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
      fprintf(stdout, "Usage: ./%s <file>\n", argv[0]);
      return 0;
    }

    /* Initialization */
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    if(!(fd = fopen(argv[1], "r"))) {
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
    
    fprintf(stdout, "Key fingerprint: %s\n", fingerprint);

    CRYPTO_cleanup_all_ex_data();
    EVP_cleanup();

    return 0;

}

