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


static int do_encrypt(int argc, char **argv)
{
  MKey_Error err;
  MKey_DataBlock in_text, out_text;
  long kvno;
  char buf[1024], *x;
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

  err = mkey_encrypt(argv[1], kvno, &in_text, &out_text);
  if (err) {
    fprintf(stderr, "%s %d: %s\n", argv[1], kvno, error_message(err));
  } else {
    write(1, buf, out_text.size);
  }
  return 0;
}


static int do_decrypt(int argc, char **argv)
{
  MKey_Error err;
  MKey_DataBlock in_text, out_text;
  long kvno;
  char buf[1024], *x;
  int n;

  if (argc != 3 || !argv[1][0] || !argv[2][0]) {
    fprintf(stderr, "usage: decrypt tag kvno\n");
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

  err = mkey_decrypt(argv[1], kvno, &in_text, &out_text);
  if (err) {
    fprintf(stderr, "%s %d: %s\n", argv[1], kvno, error_message(err));
  } else {
    write(1, buf, out_text.size);
  }
  return 0;
}


static int do_add(int argc, char **argv)
{
  krb5_error_code kerr;
  krb5_enctype enctype;
  krb5_keyblock key;
  krb5_salt salt;
  MKey_Error err;
  MKey_DataBlock keydata;
  long kvno;
  char pwstring[1024];
  char *x;

  if (argc < 4 || argc > 5 || !argv[1][0] || !argv[2][0] || !argv[3][0]) {
    fprintf(stderr, "usage: add tag kvno enctype [salt]\n");
    return 0;
  }
  kvno = strtol(argv[2], &x, 10);
  if (*x || kvno < 0 || kvno > 0x7fffffff) {
    fprintf(stderr, "invalid kvno %s\n", argv[2]);
    return 0;
  }
  kerr = krb5_string_to_enctype(krb5ctx, argv[3], &enctype);
  if (kerr) {
    fprintf(stderr, "%s: %s", argv[3], error_message(err));
    return 0;
  }
  if (argc < 5) {
    salt.salttype = KRB5_PW_SALT;
    salt.saltvalue.data = NULL;
    salt.saltvalue.length = 0;
  } else {
    salt.salttype = KRB5_PW_SALT;
    salt.saltvalue.data = argv[4];
    salt.saltvalue.length = strlen(argv[4]);
  }

  if (des_read_pw_string(pwstring, sizeof(pwstring), "Password: ", 1))
    return 0;
  krb5_string_to_key_salt(krb5ctx, enctype, pwstring, salt, &key);
  keydata.data = key.keyvalue.data;
  keydata.size = key.keyvalue.length;
  err = mkey_add_key(argv[1], kvno, enctype, &keydata);
  krb5_free_keyblock_contents(krb5ctx, &key);

  if (err) {
    fprintf(stderr, "%s %d: %s\n", argv[1], kvno, error_message(err));
  } else {
    printf("%s %d: key added\n", argv[1], kvno);
  }
  return 0;
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
    printf("%-30s %4d %s", tag, keys[i].kvno,
           kerr ? error_message(kerr) : etype);
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
    "encrypt",    do_encrypt,      "encrypt tag kvno",
    "Encrypt data using the specified tag and kvno.  Plaintext is\n"
    "read from stdin, and ciphertext written to stdout."
  },
  {
    "decrypt",    do_decrypt,      "decrypt tag kvno",
    "Decrypt data using the specified tag and kvno.  Ciphertext is\n"
    "read from stdin, and plaintext written to stdout."
  },
  {
    "add",        do_add,          "add tag kvno enctype",
    "Add a key for the specified tag and kvno to the mkey server.\n"
    "The key is obtained by prompting for a password to be converted\n"
    "to a key of the specified enctype."
  },
  {
    "remove",     do_remove,       "remove tag kvno",
    "Remove the key for the specified tag and kvno from the mkey server."
  },
  {
    "list",       do_list,         "list [tag]",
    "List current keys for the specified tag.  If no tag is given, all\n"
    "keys are listed."
  },
  {
    "shutdown",   do_shutdown,     "shutdown",
    "Shut down the master key server."
  },
  { "help",       do_help,         "help" },
  { "?"},
  { "exit",       do_exit,         "exit" },
  { "quit" },
  { NULL }
};


int main(int argc, char **argv)
{
  krb5_error_code kerr;

  initialize_krb5_error_table();
  initialize_heim_error_table();
  initialize_mkey_error_table();

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
