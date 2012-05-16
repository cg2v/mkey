/* $Id$
 * Unlock the KDB by decrypting a meta key stored on a smart card.
 * Usage: unlock_kdb [<tag>]
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <openssl/rsa.h>

#include <krb5.h>
#include <hdb.h>
#include <com_err.h>
#include <libmkey.h>
#include <mkey_err.h>
#include "pkcs15-simple.h"

int main(int argc, char **argv)
{
  MKey_Error err;
  MKey_Integer meta_state, meta_kvno, meta_enctype;
  MKey_DataBlock keydata;
  struct rlimit rl;
  p15_simple_t ctx;
  struct stat sbuf;
  char *tag, namebuf[256], *filename;
  unsigned char *ciphertext, *plaintext;
  int size;;
  FILE *F;
  RSA *rsa;

  initialize_mkey_error_table();

  if (argc > 2) {
    fprintf(stderr, "Usage: %s [tag]\n", argv[0]);
    exit(1);
  }
  if (argc > 1) tag = argv[1];
  else          tag = "default";


  /* lock down! */
  if (mlockall(MCL_CURRENT | MCL_FUTURE)) {
    fprintf(stderr, "mlockall: %s\n", strerror(errno));
    exit(1);
  }
  memset(&rl, 0, sizeof(rl));
  if (setrlimit(RLIMIT_CORE, &rl)) {
    fprintf(stderr, "setrlimit: %s\n", strerror(errno));
    exit(1);
  }


  /* get current enctype, kvno, and state */
  err = mkey_get_metakey_info(tag, &meta_state, &meta_kvno, &meta_enctype);
  if (err) {
    fprintf(stderr, "%s: %s\n", tag, error_message(err));
    exit(1);
  }
  if (meta_state == 3) {
    fprintf(stderr, "%s: load in progress; try again later\n", tag);
    exit(1);
  }
  if (meta_state != 2) {
    fprintf(stderr, "%s: keys not sealed\n", tag);
    exit(1);
  }
  err = mkey_enctype_to_string(meta_enctype, namebuf, sizeof(namebuf));
  if (err) {
    fprintf(stderr, "%s: %s\n", tag, error_message(err));
    exit(1);
  }
  printf("Current key for %s is %s, kvno %d\n", tag, namebuf, meta_kvno);


  /* set up smartcard and find username */
  if (p15_simple_init(0, &ctx)) exit(1);
  if (p15_simple_getlabel(ctx, namebuf, sizeof(namebuf)-1)) {
    p15_simple_finish(ctx);
    exit(1);
  }
  printf("Hello, %s\n", namebuf);
  if (p15_simple_setkey(ctx, "KDB Access")) {
    p15_simple_finish(ctx);
    exit(1);
  }
  if (!p15_simple_can_decrypt(ctx)) {
    printf("Hm... your smart card doesn't seem to have a decryption key.\n");
    p15_simple_finish(ctx);
    exit(1);
  }
  if (p15_simple_getkeydata(ctx, &rsa)) {
    p15_simple_finish(ctx);
    exit(1);
  }
  size = RSA_size(rsa);
  RSA_free(rsa);

  /* load the encrypted data */
  filename = malloc(strlen(MKEY_DB_DIR) + strlen(tag) + strlen(namebuf) + 32);
  if (!filename) {
    fprintf(stderr, "Out of memory!\n");
    p15_simple_finish(ctx);
    exit(1);
  }
  sprintf(filename, "%s/mkey_data/%s.%s.%d",
          MKEY_DB_DIR, tag, namebuf, meta_kvno);

  if (stat(filename, &sbuf)) {
    fprintf(stderr, "%s: %s\n", filename, strerror(errno));
    p15_simple_finish(ctx);
    exit(1);
  }

  ciphertext = malloc(sbuf.st_size);
  if (!ciphertext) {
    fprintf(stderr, "%s: out of memory!\n", filename);
    p15_simple_finish(ctx);
    exit(1);
  }

  F = fopen(filename, "r");
  if (!F) {
    fprintf(stderr, "%s: %s\n", filename, strerror(errno));
    p15_simple_finish(ctx);
    exit(1);
  }

  if (fread(ciphertext, sbuf.st_size, 1, F) != 1) {
    if (feof(F))
      fprintf(stderr, "%s: unexpected EOF\n", filename);
    else
      fprintf(stderr, "%s: %s\n", filename, strerror(errno));
    fclose(F);
    p15_simple_finish(ctx);
    exit(1);
  }


  /* decrypt it */
  plaintext = malloc(size);
  if (!plaintext) {
    fprintf(stderr, "Out of memory!\n");
    exit(1);
  }
  if (p15_simple_decrypt(ctx, ciphertext, sbuf.st_size, plaintext, &size)) {
    p15_simple_finish(ctx);
    exit(1);
  }
  p15_simple_finish(ctx);
  free(ciphertext);

  keydata.data = plaintext;
  keydata.size = size;
  err = mkey_unseal_keys(tag, meta_enctype, &keydata);
  memset(plaintext, 0, size);
  free(plaintext);
  if (err) {
    fprintf(stderr, "%s: %s\n", tag, error_message(err));
    exit(1);
  }

  printf("%s: keys unlocked\n", tag);
  exit(0);
}
