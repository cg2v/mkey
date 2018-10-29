/* $Id$
 * Unlock the KDB by decrypting a meta key stored on a smart card.
 * Usage: unlock_kdb [<tag>]
 */

#define _XOPEN_SOURCE 500  // for strdup

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <regex.h>
#include <errno.h>
#include <limits.h>

#include <openssl/rsa.h>

#include <krb5.h>
#include <hdb.h>
#include <com_err.h>
#include <libmkey.h>
#include <mkey_err.h>
#include "mkey.h"
#include "libp11.h"

//#define MKEY_PKCS11_MODULE "/usr/lib/opensc-pkcs11.so"
#define MKEY_PKCS11_MODULE "/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so"

#define lose(x) do { fprintf(stderr, "%s\n", x); goto out; } while (1)
#define flose(f,x) do { fprintf(stderr, "%s: %s\n", f, x); goto out; } while (1)

static char *db_dir = MKEY_DB_DIR;

#ifdef __GNUC__
 __attribute__((noreturn))
#endif
static void usage(char *msg) {
  FILE *F = msg ? stderr : stdout;

  if (msg) fprintf(stderr, "unlock_kdb: %s\n", msg);
  fprintf(F, "Usage: unlock_kdb [-D dir] [-s sock] [-t token] [tag]\n");
  fprintf(F, "       unlock_kdb -h\n");
  fprintf(F, "   -h       Print this help message\n");
  fprintf(F, "   -s sock  mkey server socket name [%s]\n", MKEY_SOCKET);
  fprintf(F, "   -t token Select PKCS#11 token slot\n");
  fprintf(F, "   -D dir   Specify database directory [%s]\n", MKEY_DB_DIR);
  fprintf(F, "   -F file  Specify encrypted data file\n");
  exit(!!msg);
}

/*
 * Load ciphertext into memory and attempt to decrypt it.
 * Returns the size of the plaintext, or -1 on error.
 */
static int try_decrypt(char *filename, unsigned char *plaintext,
                       RSA *key)
{
  struct stat sbuf;
  unsigned char *ciphertext = NULL;
  int plainsize;
  FILE *F = NULL;

  if (stat(filename, &sbuf))
    flose(filename, strerror(errno));

  if (!sbuf.st_size)
    flose(filename, "empty file");

  if (sbuf.st_size < 0 || sbuf.st_size > INT_MAX)
    flose(filename, "invalid file size");

  if (!(ciphertext = malloc(sbuf.st_size)))
    flose(filename, "out of memory");

  if (!(F = fopen(filename, "r")))
    flose(filename, strerror(errno));

  if (fread(ciphertext, sbuf.st_size, 1, F) != 1) {
    if (feof(F))
      flose(filename, "unexpected EOF");
    else
      flose(filename, strerror(errno));
  }
  fclose(F);

  plainsize = RSA_private_decrypt(sbuf.st_size, ciphertext, plaintext,
                                     key, RSA_PKCS1_PADDING);
  free(ciphertext);
  if (plainsize < 0)
    flose(filename, "decryption failed");
  return plainsize;

out:
  if (F) fclose(F);
  if (ciphertext) free(ciphertext);
  return -1;
}

int main(int argc, char **argv)
{
  MKey_Error err;
  MKey_Integer meta_state, meta_kvno, meta_enctype;
  MKey_DataBlock keydata;
  struct rlimit rl;
  char *tag, namebuf[256], *username = NULL, *fnpat = NULL, *filename = NULL;
  unsigned char *plaintext = NULL;
  int keysize, plainsize, status = 1;
  PKCS11_CTX *ctx = NULL;
  PKCS11_SLOT *slots = NULL, *slot = NULL;
  PKCS11_KEY *keys = NULL, *key = NULL;
  EVP_PKEY *keyobj = NULL;
  RSA *rsakey = NULL;
  unsigned int nslots, nkeys, i;
  int opt, loaded = 0, slotix = -1;


  initialize_mkey_error_table();

  opterr = 0;
  while ((opt = getopt(argc, argv, "hs:t:D:F:")) != -1) {
    switch (opt) {
      case 'D': db_dir = optarg; continue;
      case 'F': filename = optarg; continue;
      case 's': mkey_set_socket_name(optarg); continue;
      case 't': slotix = atoi(optarg); continue;
      case 'h': usage(0);
      default:  usage("unknown option");
    }
  }
  if (argc - optind > 2)
    usage("Too many arguments!");

  if (argc > optind) tag = argv[optind];
  else               tag = "default";


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
  if (!(ctx = PKCS11_CTX_new())) exit(1);
  if (PKCS11_CTX_load(ctx, MKEY_PKCS11_MODULE)) {
    fprintf(stderr, "Failed to load PKCS#11 module: %s\n",
            ERR_reason_error_string(ERR_get_error()));
    goto out;
  }
  loaded = 1;

  if (PKCS11_enumerate_slots(ctx, &slots, &nslots))
    lose("no slots available");

  if (slotix < 0) {
    if (!(slot = PKCS11_find_token(ctx, slots, nslots)) || !slot->token)
      goto out;
  } else if ((unsigned int) slotix >= nslots) {
    lose("slot index out of range");
  } else {
    slot = &slots[slotix];
  }

  if ((username = strchr(slot->token->label, ' '))) {
    int l = username - slot->token->label;

    if ((username = malloc(l + 1))) {
      strncpy(username, slot->token->label, l);
      username[l] = 0;
    }
  } else {
    username = strdup(slot->token->label);
  }
  if (!username) lose("out of memory");
  printf("Hello, %s\n", username);

  if (slot->token->loginRequired) {
    char prompt[80];
    char pincode[80];

    sprintf(prompt, "Enter PIN [%s]: ", slot->token->label);
    if (mkey_read_pw_string(pincode, sizeof(pincode), prompt, 0))
      goto out;
    if (strlen(pincode) == 0) {
      fprintf(stderr, "Pin entry aborted\n");
      goto out;
    }

    err = PKCS11_login(slot, 0, pincode);
    memset(pincode, 0, sizeof(pincode));
    if (err) lose("PIN verification failed");
  }

  /* find the KDB access key */
  if (PKCS11_enumerate_keys(slot->token, &keys, &nkeys))
    lose("unable to enumerate keys");
  for (i = 0; i < nkeys; i++) {
    if (keys[i].label && !strcmp(keys[i].label, "KEY MAN key")) {
      key = &keys[i];
      break;
    }
  }
  if (!key)
    lose("unable to find KDB access key");
  if (PKCS11_get_key_type(key) != EVP_PKEY_RSA)
    lose("KDB access key is not an RSA key");
  keyobj = PKCS11_get_private_key(key);
  if (!keyobj)
    lose("Cannot get key wrapper object for KDB access key");

  rsakey = EVP_PKEY_get0_RSA(keyobj);
  keysize = RSA_size(rsakey);
  if (!(plaintext = malloc(keysize)))
    lose("out of memory");

  if (filename) {
    plainsize = try_decrypt(filename, plaintext, rsakey);
    if (plainsize < 0) goto out;

  } else {
    int fnsize = 0, dirlen, l;
    regex_t fnreg;
    struct dirent *de;
    DIR *D;

    // XXX we really should validate and escape tag and username
    fnpat = malloc(strlen(tag) + strlen(username) + 40);
    if (!fnpat) lose("out of memory");
    sprintf(fnpat, "%s\\.%s(\\+.*)?\\.%d", tag, username, meta_kvno);
    fprintf(stderr, "Pattern: /%s/\n", fnpat);
    if ((err = regcomp(&fnreg, fnpat, REG_EXTENDED|REG_NOSUB))) {
      regerror(err, &fnreg, namebuf, sizeof(namebuf));
      lose(namebuf);
    }

    plainsize = 0;
    filename = NULL;
    dirlen = strlen(db_dir);
    if (!(D = opendir(db_dir))) {
      regfree(&fnreg);
      flose(db_dir, strerror(errno));
    }

    while ((de = readdir(D))) {
      fprintf(stderr, "Considering '%s'\n", de->d_name);
      if (regexec(&fnreg, de->d_name, 0, NULL, 0)) {
        fprintf(stderr, "No match\n");
        continue;
      }

      l = dirlen + strlen(de->d_name) + 2;
      if (fnsize < l) {
        filename = realloc(filename, l);
        if (!filename) {
          closedir(D);
          regfree(&fnreg);
          lose("out of memory");
        }
        fnsize = l;
        strcpy(filename, db_dir);
        filename[dirlen] = '/';
      }
      strcpy(filename + dirlen + 1, de->d_name);
      plainsize = try_decrypt(filename, plaintext, rsakey);
      if (plainsize > 0) break;
    }
    closedir(D);
    regfree(&fnreg);
    if (plainsize <= 0)
      lose("unable to decrypt any key data");
  }

  keydata.data = plaintext;
  keydata.size = plainsize;
  err = mkey_unseal_keys(tag, meta_enctype, &keydata);
  memset(plaintext, 0, plainsize);
  if (err)
    flose(tag, error_message(err));

  printf("%s: keys unlocked\n", tag);
  status = 0;

out:
  if (plaintext) free(plaintext);
  if (fnpat) free(fnpat);
  if (username) free(username);
  if (keyobj) EVP_PKEY_free(keyobj);
  if (slots) PKCS11_release_all_slots(ctx, slots, nslots);
  if (loaded) PKCS11_CTX_unload(ctx);
  if (ctx) PKCS11_CTX_free(ctx);
  exit(status);
}
