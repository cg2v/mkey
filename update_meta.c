/* $Id$
 * Generate and install new KDB meta-key
 * Usage: update_meta <tag> <enctype>
 */

#include <sys/resource.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <krb5.h>
#include <hdb.h>
#include <libmkey.h>
#include <mkey_err.h>
#include <com_err.h>


static int encrypt_one(char *tag, char *user, int kvno, MKey_DataBlock *key)
{
  unsigned char *buf = 0;
  char *keyfile = 0, *datafile = 0;
  RSA *rsa = 0;
  FILE *F = 0;
  int l, err;

  printf("Encrypting for %s...\n", user);

  err = ENOMEM;
  l = strlen(HDB_DB_DIR) + strlen(user) + strlen(tag) + 32;
  keyfile = malloc(l);
  if (!keyfile)  { err = ENOMEM; goto out; }
  datafile = malloc(l);
  if (!datafile) { err = ENOMEM; goto out; }
  sprintf(keyfile, "%s/mkey_public/%s", HDB_DB_DIR, user);
  sprintf(datafile, "%s/mkey_data/%s.%s.%d", HDB_DB_DIR, tag, user, kvno);

  F = fopen(keyfile, "r");
  if (!F) { err = errno; goto out; }
  rsa = PEM_read_RSA_PUBKEY(F, 0, 0, 0);
  if (!rsa) { err = -1; goto out; }
  fclose(F); F = 0;

  l = RSA_size(rsa);
  buf = malloc(l);
  if (!buf) { err = ENOMEM; goto out; }
  l = RSA_public_encrypt(key->size, key->data, buf, rsa, RSA_PKCS1_PADDING);
  if (l < 0) { err = -1; goto out; }

  F = fopen(datafile, "w");
  if (!F) { err = errno; goto out; }
  if (fwrite(buf, l, 1, F) <= 0) { err = errno; goto out; }
  err = 0;

out:
  if (F)        fclose(F);
  if (rsa)      RSA_free(rsa);
  if (buf)      free(buf);
  if (err && datafile) unlink(datafile);
  if (datafile) free(datafile);
  if (keyfile)  free(keyfile);
  return err;
}


int main(int argc, char **argv) {
  struct rlimit rl;
  MKey_Error err;
  MKey_DataBlock keydata;
  MKey_Integer enctype, meta_enctype, meta_kvno, meta_state;
  char *tag, *etypestr;

  initialize_mkey_error_table();

  /* check arguments */
  if (argc != 3) {
    fprintf(stderr, "Usage: %s <tag> <enctype>\n", argv[0]);
    exit(1);
  }
  tag = argv[1];
  etypestr = argv[2];

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

  /* convert the requested enctype */
  err = mkey_string_to_enctype(etypestr, &enctype);
  if (err) {
    fprintf(stderr, "%s: %s\n", etypestr, error_message(err));
    exit(1);
  }

  /* get current meta key info */
  err = mkey_get_metakey_info(tag, &meta_state, &meta_kvno, &meta_enctype);
  if (err) {
    fprintf(stderr, "%s: %s\n", etypestr, error_message(err));
    exit(1);
  }
  if (meta_state > 1) {
    fprintf(stderr, "%s: keys are not unsealed\n", tag);
    exit(1);
  }
  meta_kvno++;
  printf("New meta kvno for %s will be %d\n", tag, meta_kvno);

  /* generate a key */
  memset(&keydata, 0, sizeof(keydata));
  keydata.size = 1024;
  keydata.data = malloc(keydata.size);
  if (!keydata.data) {
    fprintf(stderr, "%s: %s\n", etypestr, strerror(ENOMEM));
    exit(1);
  }
  err = mkey_generate_key(enctype, &keydata);
  if (err) {
    fprintf(stderr, "%s: %s\n", etypestr, error_message(err));
    exit(1);
  }

  /* XXX encrypt it for each user */
  err = encrypt_one(tag, "jhutz", meta_kvno, &keydata);
  if (err == -1) {
    fprintf(stderr, "%s: OpenSSL failure; details follow...\n", "jhutz");
    ERR_print_errors_fp(stderr);
    exit(1);
  } else if (err) {
    fprintf(stderr, "%s: %s\n", "jhutz", error_message(err));
    exit(1);
  }

  /* update mkeyd */
  err = mkey_set_metakey(tag, meta_kvno, enctype, &keydata);
  if (err) {
    fprintf(stderr, "%s: %s\n", etypestr, error_message(err));
    exit(1);
  }
  printf("New meta key set for %s\n", tag);

  /* rewrite meta meytab */
  err = mkey_store_keys(tag);
  if (err) {
    fprintf(stderr, "%s: %s\n", etypestr, error_message(err));
    exit(1);
  }
  printf("Master keytab for %s has been written with new meta kvno %d\n",
         tag, meta_kvno);
  exit(0);
}
