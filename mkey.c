/* mkey - Kerberos master key manager
 * Copyright (c) 2003 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software_Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 * 
 * $Id$
 * master key maintenance client
 */


#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <com_err.h>
#include <krb5.h>
#include <des.h>
#include <sl.h>

#include "libmkey.h"
#include "mkey_err.h"


krb5_context krb5ctx;

static SL_cmd commands[];


static void print_key(void *data, int len)
{
  unsigned char *bytes = data;
  int i;

  for (i = 0; i < len; i++)
    printf("%s%02x", i ? i%16 ? ":" : "\n  " : "  ", bytes[i]);
  printf("\n");
}


static int get_key(char *etypestr, char *saltstr, char *keystr, int randkey,
                   krb5_enctype *enctype, MKey_DataBlock *key)
{
  krb5_keyblock keyblock;
  krb5_error_code err;
  krb5_salt salt;
  char buf[1024];
  unsigned char *data;
  int i, j, d;

  err = krb5_string_to_enctype(krb5ctx, etypestr, enctype);
  if (err) {
    fprintf(stderr, "%s: %s\n", etypestr, error_message(err));
    return 1;
  }

  if (randkey) {
    key->data = malloc(1024);
    if (!key->data) {
      fprintf(stderr, "get_key: out of memory\n");
      return 1;
    }
    key->size = 1024;
    err = mkey_generate_key(*enctype, key);
    if (err) {
      fprintf(stderr, "get_key: %s\n", error_message(err));
      return 1;
    }
  } else if (keystr) {
    memset(key, 0, sizeof(*key));
    data = malloc(strlen(keystr));
    if (!data) {
      fprintf(stderr, "get_key: out of memory\n");
      return 1;
    }
    for (i = j = 0; keystr[i]; i++) {
      if      (keystr[i] == ':' || keystr[i] == ' ') continue;
      else if (keystr[i] >= '0' && keystr[i] <= '9') d = keystr[i] - '0';
      else if (keystr[i] >= 'a' && keystr[i] <= 'f') d = keystr[i] - 'a' + 10;
      else if (keystr[i] >= 'A' && keystr[i] <= 'F') d = keystr[i] - 'A' + 10;
      else {
        fprintf(stderr, "%s: invalid key string\n", keystr);
        free(data);
        return 1;
      }
      if (keystr[i+1] == ':' || keystr[i+1] == ' ' || !keystr[i+1]) {
        data[j++] = d;
        continue;
      }

      i++;
      d <<= 4;
      if      (keystr[i] >= '0' && keystr[i] <= '9') d += keystr[i] - '0';
      else if (keystr[i] >= 'a' && keystr[i] <= 'f') d += keystr[i] - 'a' + 10;
      else if (keystr[i] >= 'A' && keystr[i] <= 'F') d += keystr[i] - 'A' + 10;
      else {
        fprintf(stderr, "%s: invalid key string\n", keystr);
        free(data);
        return 1;
      }
      data[j++] = d;
    }
    key->data = data;
    key->size = j;
  } else {
    memset(&salt, 0, sizeof(salt));
    salt.salttype = KRB5_PW_SALT;
    salt.saltvalue.data = saltstr;
    salt.saltvalue.length = saltstr ? strlen(saltstr) : 0;

    if (des_read_pw_string(buf, sizeof(buf), "Password: ", 1))
      return 1;
    err = krb5_string_to_key_salt(krb5ctx, *enctype, buf, salt, &keyblock);
    if (err) {
      fprintf(stderr, "string_to_key: %s\n", error_message(err));
      return 1;
    }
    key->data = keyblock.keyvalue.data;
    key->size = keyblock.keyvalue.length;
  }
  return 0;
}



static int encrypt_decrypt(int argc, char **argv, int mode)
{
  MKey_Error err;
  MKey_DataBlock in_text, out_text;
  long kvno;
  unsigned char buf[1024];
  char *x;
  int n;

  if (argc != 3 || !argv[1][0] || !argv[2][0]) {
    fprintf(stderr, "usage: encrypt tag kvno\n");
    return 0;
  }
  kvno = strtol(argv[2], &x, 10);
  if (*x || kvno < 0 || kvno > 0x7fffffff) {
    fprintf(stderr, "invalid kvno %s\n", argv[2]);
    return 0;
  }

  n = read(0, buf, sizeof(buf));
  if (n < 0) {
    fprintf(stderr, "stdin: %s\n", error_message(errno));
    return 0;
  }

  in_text.data = buf;
  in_text.size = n;
  out_text.data = buf;
  out_text.size = sizeof(buf);

  if (mode)
    err = mkey_encrypt(argv[1], kvno, &in_text, &out_text);
  else
    err = mkey_decrypt(argv[1], kvno, &in_text, &out_text);
  if (err) {
    fprintf(stderr, "%s %d: %s\n", argv[1], kvno, error_message(err));
  } else {
    write(1, buf, out_text.size);
  }
  return 0;
}

static int do_encrypt(int argc, char **argv)
{
  return encrypt_decrypt(argc, argv, 1);
}

static int do_decrypt(int argc, char **argv)
{
  return encrypt_decrypt(argc, argv, 0);
}



static int key_entry_cmd(int argc, char **argv, int mode, char *okmsg)
{
  krb5_enctype enctype;
  MKey_Error err;
  MKey_DataBlock keydata;
  char *tag = 0, *kvnostr = 0, *etypestr = 0, *saltstr = 0, *keystr = 0;
  char *cmd, *x;
  int randkey = 0;
  long kvno;

  cmd = argv[0]; argv++; argc--;
  if      (argc > 1 && !strcmp(argv[0], "-k")) {
    keystr  = argv[1];
    argv += 2; argc -= 2;
  } else if (argc > 1 && !strcmp(argv[0], "-s")) {
    saltstr = argv[1];
    argv += 2; argc -= 2;
  } else if (argc && !strcmp(argv[0], "-r")) {
    randkey = 1;
    argv += 1; argc -= 1;
  }

  if (argc)             { tag      = argv[0]; argv++; argc--; }
  if (argc && mode > 0) { kvnostr  = argv[0]; argv++; argc--; }
  if (argc)             { etypestr = argv[0]; argv++; argc--; }
  if (argc || !tag || !etypestr
  ||  (mode > 0 && !kvnostr) || (mode != 2 && randkey)) {
    fprintf(stderr, "usage: %s [%s-k key | -s salt] tag%s enctype\n",
            cmd, mode == 2 ? "-r | " : "", mode ? " kvno" : "");
    return 0;
  }

  if (mode > 0) {
    kvno = strtol(kvnostr, &x, 10);
    if (*x || kvno < 0 || kvno > 0x7fffffff) {
      fprintf(stderr, "invalid kvno %s\n", kvnostr);
      return 0;
    }
  }

  if (get_key(etypestr, saltstr, keystr, randkey, &enctype, &keydata))
    return 0;

  switch (mode) {
    case 0: err = mkey_unseal_keys(tag, enctype, &keydata);       break;
    case 1: err = mkey_set_metakey(tag, kvno, enctype, &keydata); break;
    case 2: err = mkey_add_key(tag, kvno, enctype, &keydata);     break;
  }

  free(keydata.data);

  if (err) {
    if (mode > 0)
      fprintf(stderr, "%s %d: %s\n", tag, kvno, error_message(err));
    else
      fprintf(stderr, "%s: %s\n", tag, error_message(err));
  } else if (okmsg) {
    if (mode > 0)
      printf("%s %d: %s\n", tag, kvno, okmsg);
    else
      printf("%s: %s\n", tag, okmsg);
  }
  return 0;
}

static int do_add(int argc, char **argv)
{
  return key_entry_cmd(argc, argv, 2, "key added");
}


static int do_remove(int argc, char **argv)
{
  MKey_Error err;
  long kvno;
  char *x;

  if (argc != 3 || !argv[1][0] || !argv[2][0]) {
    fprintf(stderr, "usage: remove tag kvno\n");
    return 0;
  }
  kvno = strtol(argv[2], &x, 10);
  if (*x || kvno < 0 || kvno > 0x7fffffff) {
    fprintf(stderr, "invalid kvno %s\n", argv[2]);
    return 0;
  }
  err = mkey_remove_key(argv[1], kvno);
  if (err) {
    fprintf(stderr, "%s %d: %s\n", argv[1], kvno, error_message(err));
  } else {
    printf("%s %d: key removed\n", argv[1], kvno);
  }
  return 0;
}


static int do_verify(int argc, char **argv)
{
  MKey_Error err;
  long kvno;
  char *x;

  if (argc != 3 || !argv[1][0] || !argv[2][0]) {
    fprintf(stderr, "usage: verify tag kvno\n");
    return 0;
  }
  kvno = strtol(argv[2], &x, 10);
  if (*x || kvno < 0 || kvno > 0x7fffffff) {
    fprintf(stderr, "invalid kvno %s\n", argv[2]);
    return 0;
  }
  err = mkey_verify_key(argv[1], kvno);
  if (err) {
    fprintf(stderr, "%s %d: %s\n", argv[1], kvno, error_message(err));
  } else {
    printf("%s %d: key exists\n", argv[1], kvno);
  }
  return 0;
}


static void list_keys_for_tag(char *tag)
{
  MKey_Error err;
  MKey_KeyInfo keys[256];
  MKey_Integer nkeys;
  krb5_error_code kerr;
  char *etype;
  int i;

  nkeys = 256;
  err = mkey_list_keys(tag, &nkeys, keys);
  if (err) {
    fprintf(stderr, "%s: %s\n", tag, error_message(err));
    return;
  }
  for (i = 0; i < nkeys; i++) {
    kerr = krb5_enctype_to_string(krb5ctx, keys[i].enctype, &etype);
    if (kerr)
      fprintf(stderr, "%-30s %4d %s\n", tag, keys[i].kvno, error_message(kerr));
    else
      printf("%-30s %4d %s\n", tag, keys[i].kvno, etype);
  }
}


static int do_list(int argc, char **argv)
{
  MKey_Error err;
  char tagbuf[512];
  int i;

  if (argc > 2) {
    fprintf(stderr, "usage: list [tag]\n");
    return 0;
  }

  if (argc > 1) list_keys_for_tag(argv[1]);
  else for (i = 0;; i++) {
    err = mkey_list_tag(i, tagbuf, sizeof(tagbuf));
    if (err == MKEY_ERR_TAG_RANGE) break;
    if (err == MKEY_ERR_NO_TAG) continue;
    if (err) fprintf(stderr, "tag %d: %s\n", i, error_message(err));
    else list_keys_for_tag(tagbuf);
  }

  return 0;
}


static int do_e2str(int argc, char **argv)
{
  MKey_Error err;
  long enctype;
  char etypestr[256], *x;

  if (argc != 2) {
    fprintf(stderr, "usage: etype2str enctype-number\n");
    return 0;
  }

  enctype = strtol(argv[1], &x, 10);
  if (*x || enctype < 0 || enctype > 0x7fffffff) {
    fprintf(stderr, "invalid enctype %s\n", argv[1]);
    return 0;
  }

  err = mkey_enctype_to_string(enctype, etypestr, sizeof(etypestr));
  if (err) {
    fprintf(stderr, "mkey_enctype_to_string: %s\n", error_message(err));
  } else {
    printf("%d -> %s\n", enctype, etypestr);
  }
  return 0;
}


static int do_str2e(int argc, char **argv)
{
  MKey_Integer enctype;
  MKey_Error err;

  if (argc != 2) {
    fprintf(stderr, "usage: str2etype enctype\n");
    return 0;
  }

  err = mkey_string_to_enctype(argv[1], &enctype);
  if (err) {
    fprintf(stderr, "mkey_string_to_enctype: %s\n", error_message(err));
  } else {
    printf("%s -> %d\n", argv[1], enctype);
  }
  return 0;
}


static int do_str2k(int argc, char **argv)
{
  krb5_enctype enctype;
  MKey_DataBlock keydata;
  char *etypestr = 0, *saltstr = 0, *keystr = 0;

  argv++; argc--;
  if      (argc > 1 && !strcmp(argv[0], "-k")) {
    keystr  = argv[1];
    argv += 2; argc -= 2;
  } else if (argc > 1 && !strcmp(argv[0], "-s")) {
    saltstr = argv[1];
    argv += 2; argc -= 2;
  }

  if (argc) { etypestr = argv[0]; argv++; argc--; }
  if (argc || !etypestr) {
    fprintf(stderr, "usage: str2key [-k key | -s salt] enctype\n");
    return 0;
  }

  if (get_key(etypestr, saltstr, keystr, 0, &enctype, &keydata))
    return 0;

  print_key(keydata.data, keydata.size);
  free(keydata.data);
  return 0;
}


static int do_genkey(int argc, char **argv)
{
  MKey_Error err;
  MKey_DataBlock key;
  krb5_enctype enctype;

  if (argc != 2) {
    fprintf(stderr, "usage: genkey enctype\n");
    return 0;
  }

  if (get_key(argv[1], 0, 0, 1, &enctype, &key))
    return 0;

  print_key((unsigned char *)key.data, key.size);
  free(key.data);
  return 0;
}


static int do_getmeta(int argc, char **argv)
{
  MKey_Integer kvno, enctype, state;
  MKey_Error err;
  char *statestr;
  char *etype;

  if (argc != 2) {
    fprintf(stderr, "usage: getmeta tag\n");
    return 0;
  }

  err = mkey_get_metakey_info(argv[1], &state, &kvno, &enctype);
  if (err) {
    fprintf(stderr, "%s: %s\n", argv[1], error_message(err));
    return 0;
  }

  switch (state) {
    case 0: statestr  = "keys not sealed; meta key not set"; break;
    case 1: statestr  = "keys not sealed; meta key set";     break;
    case 2: statestr  = "key sealed";                        break;
    default: statestr = "state unknown";
  }

  err = krb5_enctype_to_string(krb5ctx, enctype, &etype);
  if (err) {
    fprintf(stderr, "%s: etype %d: %s\n", argv[1], enctype, error_message(err));
    return 0;
  }

  printf("%s meta kvno=%d (%s) -- %s (%d)\n",
         argv[1], kvno, etype, statestr, state);
  return 0;
}


static int do_unseal(int argc, char **argv)
{
  return key_entry_cmd(argc, argv, 0, "keys unsealed");
}


static int do_setmeta(int argc, char **argv)
{
  return key_entry_cmd(argc, argv, 1, "meta key set");
}


static int do_store(int argc, char **argv)
{
  MKey_Error err;

  if (argc != 2) {
    fprintf(stderr, "usage: store tag\n");
    return 0;
  }

  err = mkey_store_keys(argv[1]);
  if (err) {
    fprintf(stderr, "%s: %s\n", argv[1], error_message(err));
  } else {
    printf("%s: keys stored\n", argv[1]);
  }
  return 0;
}


static int do_shutdown(int argc, char **argv)
{
  MKey_Error err;

  if (argc != 1) {
    fprintf(stderr, "usage: shutdown\n");
    return 0;
  }
  err = mkey_shutdown();
  if (err) {
    fprintf(stderr, "%s\n", error_message(err));
    return 0;
  }
  return 0;
}


static int do_help(int argc, char **argv)
{
  sl_help(commands, argc, argv);
  return 0;
}


static int do_exit(int argc, char **argv)
{
  return 1;
}


static SL_cmd commands[] = {
  {
    "encrypt",    do_encrypt,    "encrypt tag kvno",
    "Encrypt data using the specified tag and kvno.  Plaintext is\n"
    "read from stdin, and ciphertext written to stdout."
  },
  {
    "decrypt",    do_decrypt,    "decrypt tag kvno",
    "Decrypt data using the specified tag and kvno.  Ciphertext is\n"
    "read from stdin, and plaintext written to stdout."
  },
  {
    "add",        do_add,        "add [-r | -k key | -s salt] tag kvno enctype",
    "Add a key for the specified tag and kvno to the mkey server.\n"
    "The key may be provided as a hexadecimal string using the -k option;\n"
    "otherwise it is obtained by prompting for a password to be converted\n"
    "to a key of the specified enctype.  The -s option may be used to set\n"
    "a salt string to be used; if not given, the empty string is used."
  },
  {
    "remove",     do_remove,     "remove tag kvno",
    "Remove the key for the specified tag and kvno from the mkey server."
  },
  {
    "verify",     do_verify,     "verify tag kvno",
    "Verify that a key for the specified tag and kvno exists in the server."
  },
  {
    "list",       do_list,       "list [tag]",
    "List current keys for the specified tag.  If no tag is given, all\n"
    "keys are listed."
  },
  {
    "genkey",     do_genkey,     "genkey enctype",
    "Generate a random key of the specified enctype."
  },
  {
    "etype2str",  do_e2str,      "etype2str enctype-number",
    "Print the name string for the specified enctype number."
  },
  {
    "str2etype",  do_str2e,      "str2etype enctype",
    "Print the enctype number for the specified enctype."
  },
  {
    "str2key",    do_str2k,      "str2key [-k key | -s salt] enctype",
    "Print the specified encryption key as a hex string.\n"
    "The key may be provided as a hexadecimal string using the -k option;\n"
    "otherwise it is obtained by prompting for a password to be converted\n"
    "to a key of the specified enctype.  The -s option may be used to set\n"
    "a salt string to be used; if not given, the empty string is used."
  },
  {
    "getmeta",    do_getmeta,    "getmeta tag",
    "Get the meta key version, enctype, and state of sealed keys for the\n"
    "specified tag."
  },
  {
    "unseal",     do_unseal,     "unseal [-k key | -s salt] tag enctype",
    "Unseal master keys for the specified tag using a provided meta key\n"
    "The key may be provided as a hexadecimal string using the -k option;\n"
    "otherwise it is obtained by prompting for a password to be converted\n"
    "to a key of the specified enctype.  The -s option may be used to set\n"
    "a salt string to be used; if not given, the empty string is used."
  },
  {
    "setmeta",    do_setmeta,    "setmeta [-k key | -s salt] tag kvno enctype",
    "Set the meta key used to encrypt stored master keys for the specified\n"
    "tag, and associate the meta key with the given key version number.\n"
    "The key may be provided as a hexadecimal string using the -k option;\n"
    "otherwise it is obtained by prompting for a password to be converted\n"
    "to a key of the specified enctype.  The -s option may be used to set\n"
    "a salt string to be used; if not given, the empty string is used."
  },
  {
    "store",      do_store,      "store tag",
    "Store master keys for the specified tag to disk, encrypted using the\n"
    "current meta key."
  },
  {
    "shutdown",   do_shutdown,   "shutdown",
    "Shut down the master key server."
  },
  { "help",       do_help,       "help" },
  { "?"},
  { "exit",       do_exit,       "exit" },
  { "quit" },
  { NULL }
};


void usage() {
  fprintf(stderr, "Usage: mkey [-s sockname] command [args...]\n");
  exit(1);
}


int main(int argc, char **argv)
{
  krb5_error_code kerr;

  initialize_krb5_error_table();
  initialize_heim_error_table();
  initialize_mkey_error_table();

  if (argc > 1) {
    if (!strcmp(argv[1], "-h")) {
      usage();
    } else if (!strcmp(argv[1], "-s") && argc > 2) {
      mkey_set_socket_name(argv[2]);
      argv += 2;
      argc -= 2;
    } else if (argv[1][0] == '-') {
      usage();
    }
  }
  kerr = krb5_init_context(&krb5ctx);
  if (kerr) {
    fprintf(stderr, "krb5_init_context: %s\n", error_message(kerr));
    exit(1);
  }

  if (argc > 1) {
    kerr = sl_command(commands, argc - 1, argv + 1);
    if (kerr < 0)
      fprintf(stderr, "%s: unrecognized command\n", argv[1]);
  } else {
    kerr = !!sl_loop(commands, "mkey>");
  }
  krb5_free_context(krb5ctx);
  exit(kerr);
}
