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
 * master key server
 * usage: mkeyd [sock_name]
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <fcntl.h>
#include <stropts.h>
#include <pthread.h>
#include <door.h>
#include <errno.h>

#include <krb5.h>
#include <krb5_err.h>
#include <hdb.h>

#include "libmkey.h"
#include "mkey_err.h"
#include "mkey.h"

#define MAX_LIST_KEYS 512

typedef MKey_Error (*opfunc)          (MKey_Integer, char *, int, char *, int *);
static MKey_Error op_encrypt          (MKey_Integer, char *, int, char *, int *);
static MKey_Error op_decrypt          (MKey_Integer, char *, int, char *, int *);
static MKey_Error op_add_key          (MKey_Integer, char *, int, char *, int *);
static MKey_Error op_remove_key       (MKey_Integer, char *, int, char *, int *);
static MKey_Error op_list_keys        (MKey_Integer, char *, int, char *, int *);
static MKey_Error op_list_tag         (MKey_Integer, char *, int, char *, int *);
static MKey_Error op_shutdown         (MKey_Integer, char *, int, char *, int *);
static MKey_Error op_verify_key       (MKey_Integer, char *, int, char *, int *);
static MKey_Error op_generate_key     (MKey_Integer, char *, int, char *, int *);
static MKey_Error op_get_metakey_info (MKey_Integer, char *, int, char *, int *);
static MKey_Error op_unseal_keys      (MKey_Integer, char *, int, char *, int *);
static MKey_Error op_set_metakey      (MKey_Integer, char *, int, char *, int *);
static MKey_Error op_string_to_etype  (MKey_Integer, char *, int, char *, int *);
static MKey_Error op_etype_to_string  (MKey_Integer, char *, int, char *, int *);
static MKey_Error op_store_keys       (MKey_Integer, char *, int, char *, int *);
static MKey_Error op_load_keys        (MKey_Integer, char *, int, char *, int *);

static opfunc operations[] = {
  op_encrypt,          /* MKEY_OP_ENCRYPT           */
  op_decrypt,          /* MKEY_OP_DECRYPT           */
  op_add_key,          /* MKEY_OP_ADD_KEY           */
  op_remove_key,       /* MKEY_OP_REMOVE_KEY        */
  op_list_keys,        /* MKEY_OP_LIST_KEYS         */
  op_list_tag,         /* MKEY_OP_LIST_TAG          */
  op_shutdown,         /* MKEY_OP_SHUTDOWN          */
  op_verify_key,       /* MKEY_OP_VERIFY_KEY        */
  op_generate_key,     /* MKEY_OP_GENERATE_KEY      */
  op_get_metakey_info, /* MKEY_OP_GET_METAKEY_INFO  */
  op_unseal_keys,      /* MKEY_OP_UNSEAL_KEYS       */
  op_set_metakey,      /* MKEY_OP_SET_METAKEY       */
  op_string_to_etype,  /* MKEY_OP_STRING_TO_ETYPE   */
  op_etype_to_string,  /* MKEY_OP_ETYPE_TO_STRING   */
  op_store_keys,       /* MKEY_OP_STORE_KEYS        */
  op_load_keys,        /* MKEY_OP_LOAD_KEYS        */
};
#define n_operations (sizeof(operations) / sizeof(operations[0]))

struct keyinfo {
  struct keyinfo *next;
  int kvno;
  int sealed;
  pthread_mutex_t mutex;

  krb5_enctype enctype;
  krb5_keyblock key;
  krb5_crypto crypto;
};

struct taginfo {
  struct taginfo *next;
  struct keyinfo *keys;
  char *name;
  int slot;
  pthread_rwlock_t lock;

  int meta_state;
  int meta_kvno;
  krb5_enctype meta_enctype;
  krb5_keyblock meta_key;
  krb5_data challenge;
};

static char *keytab_dir = HDB_DB_DIR;
static char *sock_name = MKEY_SOCKET;
static struct taginfo *taglist;
static int max_slot;
static pthread_rwlock_t masterlock;
static pthread_key_t contextkey;

static pthread_mutex_t exit_mutex;
static pthread_cond_t exit_cv;


static MKey_Error context_setup(krb5_context *ctx)
{
  int err;

  *ctx = pthread_getspecific(contextkey);
  if (*ctx) return 0;

  err = krb5_init_context(ctx);
  if (err) return err;
  return pthread_setspecific(contextkey, *ctx);
}

static void context_destruct(void * ctx)
{
  krb5_free_context(ctx);
  pthread_setspecific(contextkey, 0);
}


static MKey_Error find_tag(char *name, struct taginfo **rtag, int create)
{
  struct taginfo *tag;
  int err;

  if (create)
    err = pthread_rwlock_wrlock(&masterlock);
  else
    err = pthread_rwlock_rdlock(&masterlock);
  if (err) return err;

  /* short circuit the case where we have not been told any keys yet,
   * and return a special error code.  This makes the KDC (only) drop
   * the request on the floor instead of returning a "not found" error.
   * That way, the client can try to find a KDC not in this state.
   */
  if (!taglist && !create) {
    pthread_rwlock_unlock(&masterlock);
    return MKEY_ERR_NO_KEYS;
  }

  for (tag = taglist; tag; tag = tag->next)
    if (!strcmp(tag->name, name)) {
      *rtag = tag;
      return pthread_rwlock_unlock(&masterlock);
    }
  if (!create) {
    pthread_rwlock_unlock(&masterlock);
    return MKEY_ERR_NO_TAG;
  }

  tag = malloc(sizeof(struct taginfo));
  if (!tag) {
    pthread_rwlock_unlock(&masterlock);
    return MKEY_ERR_NO_MEM;
  }
  memset(tag, 0, sizeof(*tag));
  tag->name = strdup(name);
  if (!tag->name) {
    free(tag);
    pthread_rwlock_unlock(&masterlock);
    return MKEY_ERR_NO_MEM;
  }
  err = pthread_rwlock_init(&tag->lock, 0);
  if (err) {
    free(tag->name);
    free(tag);
    pthread_rwlock_unlock(&masterlock);
    return err;
  }
  tag->slot = ++max_slot;
  tag->next = taglist;
  taglist = tag;
  *rtag = tag;
  return pthread_rwlock_unlock(&masterlock);
}

static MKey_Error find_tag_slot(int slot, struct taginfo **rtag)
{
  struct taginfo *tag;
  int err;

  if (slot < 0) return MKEY_ERR_TAG_RANGE;
  err = pthread_rwlock_rdlock(&masterlock);
  if (err) return err;

  if (slot > max_slot) {
    pthread_rwlock_unlock(&masterlock);
    return MKEY_ERR_TAG_RANGE;
  }
  for (tag = taglist; tag; tag = tag->next)
    if (tag->slot == slot) {
      *rtag = tag;
      return pthread_rwlock_unlock(&masterlock);
    }
  pthread_rwlock_unlock(&masterlock);
  return MKEY_ERR_NO_TAG;
}

static MKey_Error find_key(struct taginfo *tag, int kvno,
                           struct keyinfo **rkey, int create)
{
  struct keyinfo *key;
  int err;

  if (create)
    err = pthread_rwlock_wrlock(&tag->lock);
  else
    err = pthread_rwlock_rdlock(&tag->lock);
  if (err) return err;

  for (key = tag->keys; key; key = key->next)
    if (key->kvno == kvno) {
      *rkey = key;
      return pthread_rwlock_unlock(&tag->lock);
    }
  if (!create) {
    pthread_rwlock_unlock(&tag->lock);
    return MKEY_ERR_NO_KEY;
  }

  key = malloc(sizeof(struct keyinfo));
  if (!key) {
    pthread_rwlock_unlock(&tag->lock);
    return MKEY_ERR_NO_MEM;
  }
  memset(key, 0, sizeof(*key));
  err = pthread_mutex_init(&key->mutex, 0);
  if (err) {
    free(key);
    pthread_rwlock_unlock(&tag->lock);
    return err;
  }
  key->kvno = kvno;
  key->next = tag->keys;
  tag->keys = key;
  *rkey = key;
  return pthread_rwlock_unlock(&tag->lock);
}




static MKey_Error encrypt_decrypt(MKey_Integer cookie, int dir,
                                  char *reqbuf, int reqlen,
                                  char *repbuf, int *replen)
{
  MKey_Integer kvno;
  MKey_Error err;
  MKey_DataBlock data;
  char *tagname;
  struct taginfo *tag;
  struct keyinfo *key;
  krb5_context ctx;
  krb5_data res;

  err = _mkey_decode(reqbuf, reqlen, 1, &kvno, 0, 0, &data, &tagname);
  if (err) return err;

  err = find_tag(tagname, &tag, 0);
  if (err) return err;

  err = find_key(tag, kvno, &key, 0);
  if (err) return err;

  err = context_setup(&ctx);
  if (err) return err;

  /* begin critical section */
  err = pthread_mutex_lock(&key->mutex);
  if (err) return err;

  if (!key->enctype) {
    pthread_mutex_unlock(&key->mutex);
    return MKEY_ERR_NO_KEY;
  }

  if (key->sealed) {
    pthread_mutex_unlock(&key->mutex);
    return MKEY_ERR_SEALED;
  }

  if (!key->crypto) {
    err = krb5_crypto_init(ctx, &key->key, key->enctype, &key->crypto);
    if (err) {
      pthread_mutex_unlock(&key->mutex);
      return err;
    }
  }

  if (dir) 
    err = krb5_encrypt(ctx, key->crypto, HDB_KU_MKEY,
                       data.data, data.size, &res);
  else
    err = krb5_decrypt(ctx, key->crypto, HDB_KU_MKEY,
                       data.data, data.size, &res);
  if (err) {
    pthread_mutex_unlock(&key->mutex);
    return err;
  }

  err = pthread_mutex_unlock(&key->mutex);
  if (err) {
    free(res.data);
    return err;
  }
  /* end critical section */

  data.data = res.data;
  data.size = res.length;

  err = _mkey_encode(repbuf, replen, cookie, 0, 0, 0, &data, 0);
  free(res.data);
  return err;
}

static MKey_Error op_encrypt(MKey_Integer cookie, char *reqbuf, int reqlen,
                             char *repbuf, int *replen)
{
  return encrypt_decrypt(cookie, 1, reqbuf, reqlen, repbuf, replen);
}

static MKey_Error op_decrypt(MKey_Integer cookie, char *reqbuf, int reqlen,
                             char *repbuf, int *replen)
{
  return encrypt_decrypt(cookie, 0, reqbuf, reqlen, repbuf, replen);
}


static MKey_Error op_add_key(MKey_Integer cookie, char *reqbuf, int reqlen,
                             char *repbuf, int *replen)
{
  MKey_Integer intargs[2];
  MKey_Error err;
  MKey_DataBlock keydata;
  char *tagname, *etypestr;
  struct taginfo *tag;
  struct keyinfo *key;
  krb5_context ctx;
  krb5_keytype keytype;
  krb5_keyblock keyblock;

  err = _mkey_decode(reqbuf, reqlen, 2, intargs, 0, 0, &keydata, &tagname);
  if (err) return err;

  err = find_tag(tagname, &tag, 1);
  if (err) return err;

  err = find_key(tag, intargs[0], &key, 1);
  if (err) return err;

  err = context_setup(&ctx);
  if (err) return err;

  memset(&keyblock, 0, sizeof(keyblock));

  err = krb5_enctype_to_keytype(ctx, intargs[1], &keytype);
  if (err) return err;

  keyblock.keytype = keytype;
  keyblock.keyvalue.length = keydata.size;
  keyblock.keyvalue.data = malloc(keydata.size);
  if (!keyblock.keyvalue.data)
    return MKEY_ERR_NO_MEM;
  memcpy(keyblock.keyvalue.data, keydata.data, keydata.size);

  /* begin critical section */
  err = pthread_mutex_lock(&key->mutex);
  if (err) return err;

  if (key->enctype) {
    pthread_mutex_unlock(&key->mutex);
    free(keyblock.keyvalue.data);
    return MKEY_ERR_EXIST;
  }

  key->enctype = intargs[1];
  memcpy(&key->key, &keyblock, sizeof(keyblock));

  err = pthread_mutex_unlock(&key->mutex);
  if (err) return err;
  /* end critical section */

  if (krb5_enctype_to_string(ctx, intargs[1], &etypestr)) {
    syslog(LOG_INFO, "%s: added kvno %d (%d)", tagname, intargs[0], intargs[1]);
  } else {
    syslog(LOG_INFO, "%s: added kvno %d (%s)", tagname, intargs[0], etypestr);
    free(etypestr);
  }
  return _mkey_encode(repbuf, replen, cookie, 0, 0, 0, 0, 0);
}


static MKey_Error op_remove_key(MKey_Integer cookie, char *reqbuf, int reqlen,
                                char *repbuf, int *replen)
{
  MKey_Integer kvno;
  MKey_Error err;
  char *tagname;
  struct taginfo *tag;
  struct keyinfo *key;
  krb5_context ctx;

  err = _mkey_decode(reqbuf, reqlen, 1, &kvno, 0, 0, 0, &tagname);
  if (err) return err;

  err = find_tag(tagname, &tag, 0);
  if (err) return err;

  err = find_key(tag, kvno, &key, 0);
  if (err) return err;

  err = context_setup(&ctx);
  if (err) return err;

  /* begin critical section */
  err = pthread_mutex_lock(&key->mutex);
  if (err) return err;

  if (!key->enctype) {
    pthread_mutex_unlock(&key->mutex);
    return MKEY_ERR_NO_KEY;
  }

  memset(key->key.keyvalue.data, 0, key->key.keyvalue.length);
  free(key->key.keyvalue.data);
  memset(&key->key, 0, sizeof(key->key));
  key->enctype = 0;
  if (key->crypto) {
    krb5_crypto_destroy(ctx, key->crypto);
    key->crypto = 0;
  }

  err = pthread_mutex_unlock(&key->mutex);
  if (err) return err;
  /* end critical section */

  syslog(LOG_INFO, "%s: removed kvno %d", tagname, kvno);
  return _mkey_encode(repbuf, replen, cookie, 0, 0, 0, 0, 0);
}


static MKey_Error op_verify_key(MKey_Integer cookie, char *reqbuf, int reqlen,
                                char *repbuf, int *replen)
{
  MKey_Integer kvno;
  MKey_Error err;
  char *tagname;
  struct taginfo *tag;
  struct keyinfo *key;
  krb5_context ctx;

  err = _mkey_decode(reqbuf, reqlen, 1, &kvno, 0, 0, 0, &tagname);
  if (err) return err;

  err = find_tag(tagname, &tag, 0);
  if (err) return err;

  err = find_key(tag, kvno, &key, 0);
  if (err) return err;

  /* begin critical section */
  err = pthread_mutex_lock(&key->mutex);
  if (err) return err;

  if (!key->enctype) {
    pthread_mutex_unlock(&key->mutex);
    return MKEY_ERR_NO_KEY;
  }

  err = pthread_mutex_unlock(&key->mutex);
  if (err) return err;
  /* end critical section */

  return _mkey_encode(repbuf, replen, cookie, 0, 0, 0, 0, 0);
}


static MKey_Error op_list_keys(MKey_Integer cookie, char *reqbuf, int reqlen,
                               char *repbuf, int *replen)
{
  /* well, this will eat up some stack */
  MKey_Integer iresult[1 + 2*MAX_LIST_KEYS], kvno, enctype;
  MKey_Error err;
  char *tagname;
  struct taginfo *tag;
  struct keyinfo *key;
  int i, count;

  err = _mkey_decode(reqbuf, reqlen, 0, 0, 0, 0, 0, &tagname);
  if (err) return err;

  err = find_tag(tagname, &tag, 0);
  if (err) return err;

  /* begin critical section on tag */
  err = pthread_rwlock_rdlock(&tag->lock);
  if (err) return err;

  i = 1;
  count = 0;
  for (key = tag->keys; key; key = key->next) {

    /* begin critical section on key */
    err = pthread_mutex_lock(&key->mutex);
    if (err) {
      pthread_rwlock_unlock(&tag->lock);
      return err;
    }
    kvno = key->kvno;
    enctype = key->enctype;
    err = pthread_mutex_unlock(&key->mutex);
    if (err) {
      pthread_rwlock_unlock(&tag->lock);
      return err;
    }
    /* end critical section on key */

    if (!enctype) continue;

    if (count >= MAX_LIST_KEYS) {
      pthread_rwlock_unlock(&tag->lock);
      return MKEY_ERR_TOO_BIG;
    }
    iresult[i++] = kvno;
    iresult[i++] = enctype;
    count++;
  }
  iresult[0] = count;

  err = pthread_rwlock_unlock(&tag->lock);
  if (err) return err;
  /* end critical section on tag */

  return _mkey_encode(repbuf, replen, cookie, 0, i, iresult, 0, 0);
}


static MKey_Error op_list_tag(MKey_Integer cookie, char *reqbuf, int reqlen,
                              char *repbuf, int *replen)
{
  MKey_Integer slot;
  MKey_Error err;
  struct taginfo *tag;

  err = _mkey_decode(reqbuf, reqlen, 1, &slot, 0, 0, 0, 0);
  if (err) return err;

  err = find_tag_slot(slot, &tag);
  if (err) return err;

  return _mkey_encode(repbuf, replen, cookie, 0, 0, 0, 0, tag->name);
}


static MKey_Error op_shutdown(MKey_Integer cookie, char *reqbuf, int reqlen,
                              char *repbuf, int *replen)
{
  MKey_Error err;

  syslog(LOG_INFO, "shutting down");
  err = pthread_cond_signal(&exit_cv);
  if (err) return err;

  return _mkey_encode(repbuf, replen, cookie, 0, 0, 0, 0, 0);
}


static MKey_Error op_generate_key(MKey_Integer cookie, char *reqbuf, int reqlen,
                                  char *repbuf, int *replen)
{
  MKey_DataBlock keydata;
  MKey_Integer enctype;
  MKey_Error err;
  krb5_keyblock key;
  krb5_context ctx;

  err = _mkey_decode(reqbuf, reqlen, 1, &enctype, 0, 0, 0, 0);
  if (err) return err;

  err = context_setup(&ctx);
  if (err) return err;

  err = krb5_generate_random_keyblock(ctx, enctype, &key);
  if (err) return err;

  keydata.data = key.keyvalue.data;
  keydata.size = key.keyvalue.length;
  err = _mkey_encode(repbuf, replen, cookie, 0, 0, 0, &keydata, 0);
  krb5_free_keyblock_contents(ctx, &key);
  return err;
}


static MKey_Error op_get_metakey_info(MKey_Integer cookie,
                                      char *reqbuf, int reqlen,
                                      char *repbuf, int *replen)
{
  MKey_Integer iresult[3];
  MKey_Error err;
  char *tagname;
  struct taginfo *tag;
  int i, count;

  err = _mkey_decode(reqbuf, reqlen, 0, 0, 0, 0, 0, &tagname);
  if (err) return err;

  err = find_tag(tagname, &tag, 0);
  if (err) return err;

  /* begin critical section */
  err = pthread_rwlock_rdlock(&tag->lock);
  if (err) return err;

  iresult[0] = tag->meta_state;
  iresult[1] = tag->meta_kvno;
  iresult[2] = tag->meta_enctype;

  err = pthread_rwlock_unlock(&tag->lock);
  if (err) return err;
  /* end critical section */

  return _mkey_encode(repbuf, replen, cookie, 0, 3, iresult, 0, 0);
}


static MKey_Error op_unseal_keys(MKey_Integer cookie, char *reqbuf, int reqlen,
                                 char *repbuf, int *replen)
{
  MKey_Integer enctype;
  MKey_Error err, cerr;
  MKey_DataBlock keydata;
  char *tagname;
  struct taginfo *tag;
  struct keyinfo *key;
  krb5_context ctx;
  krb5_keyblock keyblock;
  krb5_keytype keytype;
  krb5_crypto crypto;
  krb5_data res;
  size_t keysize;
  int nsealed, ntotal;

  err = _mkey_decode(reqbuf, reqlen, 1, &enctype, 0, 0, &keydata, &tagname);
  if (err) return err;

  err = find_tag(tagname, &tag, 0);
  if (err) return err;

  err = context_setup(&ctx);
  if (err) return err;

  memset(&keyblock, 0, sizeof(keyblock));

  err = krb5_enctype_to_keytype(ctx, enctype, &keytype);
  if (err) return err;

  keyblock.keytype = keytype;
  keyblock.keyvalue.length = keydata.size;
  keyblock.keyvalue.data = malloc(keydata.size);
  if (!keyblock.keyvalue.data)
    return MKEY_ERR_NO_MEM;
  memcpy(keyblock.keyvalue.data, keydata.data, keydata.size);

  err = krb5_crypto_init(ctx, &keyblock, enctype, &crypto);
  if (err) {
    free(keyblock.keyvalue.data);
    return err;
  }

  /* begin critical section */
  err = pthread_rwlock_wrlock(&tag->lock);
  if (err) {
    krb5_crypto_destroy(ctx, crypto);
    free(keyblock.keyvalue.data);
  }

  if (tag->meta_state == MKEY_MSTATE_LOADING) {
    pthread_rwlock_unlock(&tag->lock);
    krb5_crypto_destroy(ctx, crypto);
    free(keyblock.keyvalue.data);
    return MKEY_ERR_LOADING;
  }

  if (tag->meta_state == MKEY_MSTATE_NEW
  ||  tag->meta_state == MKEY_MSTATE_OPEN) {
    pthread_rwlock_unlock(&tag->lock);
    krb5_crypto_destroy(ctx, crypto);
    free(keyblock.keyvalue.data);
    return MKEY_ERR_NOT_SEALED;
  }

  if (enctype != tag->meta_enctype) {
    pthread_rwlock_unlock(&tag->lock);
    krb5_crypto_destroy(ctx, crypto);
    free(keyblock.keyvalue.data);
    return MKEY_ERR_WRONG_KEY;
  }

  /* verify the challenge */
  if (tag->challenge.length) {
    err = krb5_decrypt(ctx, crypto, MKEY_KU_CHAL,
                       tag->challenge.data, tag->challenge.length, &res);
    if (err) {
      pthread_rwlock_unlock(&tag->lock);
      krb5_crypto_destroy(ctx, crypto);
      free(keyblock.keyvalue.data);
      return err;
    }
    free(res.data);
  }

  /* Now, iterate over all the keys and decrypt them */
  nsealed = ntotal = 0;
  for (key = tag->keys; key; key = key->next) {
    /* begin critical section on key */
    err = pthread_mutex_lock(&key->mutex);
    if (err) {
      pthread_rwlock_unlock(&tag->lock);
      krb5_crypto_destroy(ctx, crypto);
      free(keyblock.keyvalue.data);
      return err;
    }

    if (!key->enctype) {
      pthread_mutex_unlock(&key->mutex);
      continue;
    }
    ntotal++;

    if (!key->sealed) {
      pthread_mutex_unlock(&key->mutex);
      continue;
    }
    nsealed++;

    err = krb5_decrypt(ctx, crypto, MKEY_KU_META,
                       key->key.keyvalue.data, key->key.keyvalue.length, &res);
    if (err) {
      pthread_mutex_unlock(&key->mutex);
      pthread_rwlock_unlock(&tag->lock);
      krb5_crypto_destroy(ctx, crypto);
      free(keyblock.keyvalue.data);
      return err;
    }
    err = krb5_enctype_keysize(ctx, key->key.keytype, &keysize);
    if (!err && keysize > res.length) err = KRB5_BAD_KEYSIZE;
    if (err) {
      pthread_mutex_unlock(&key->mutex);
      pthread_rwlock_unlock(&tag->lock);
      free(res.data);
      krb5_crypto_destroy(ctx, crypto);
      free(keyblock.keyvalue.data);
      return err;
    }

    memset(key->key.keyvalue.data, 0, key->key.keyvalue.length);
    free(key->key.keyvalue.data);
    key->key.keyvalue = res;
    key->key.keyvalue.length = keysize;
    key->sealed = 0;

    err = pthread_mutex_unlock(&key->mutex);
    if (err) {
      pthread_rwlock_unlock(&tag->lock);
      krb5_crypto_destroy(ctx, crypto);
      free(keyblock.keyvalue.data);
      return err;
    }
    /* end critical section on key */
  }

  tag->meta_state = MKEY_MSTATE_OPEN;
  tag->meta_key = keyblock;

  err = pthread_rwlock_unlock(&tag->lock);
  /* end critical section */

  krb5_crypto_destroy(ctx, crypto);
  if (err) return err;

  syslog(LOG_INFO, "%s: unsealed %d/%d keys", tagname, nsealed, ntotal);
  return _mkey_encode(repbuf, replen, cookie, 0, 0, 0, 0, 0);
}


static MKey_Error op_set_metakey(MKey_Integer cookie, char *reqbuf, int reqlen,
                                 char *repbuf, int *replen)
{
  MKey_Integer intargs[2];
  MKey_Error err;
  MKey_DataBlock keydata;
  char *tagname, *etypestr;
  struct taginfo *tag;
  krb5_context ctx;
  krb5_keytype keytype;
  krb5_keyblock keyblock;

  err = _mkey_decode(reqbuf, reqlen, 2, intargs, 0, 0, &keydata, &tagname);
  if (err) return err;

  err = find_tag(tagname, &tag, 1);
  if (err) return err;

  err = context_setup(&ctx);
  if (err) return err;

  memset(&keyblock, 0, sizeof(keyblock));

  err = krb5_enctype_to_keytype(ctx, intargs[1], &keytype);
  if (err) return err;

  keyblock.keytype = keytype;
  keyblock.keyvalue.length = keydata.size;
  keyblock.keyvalue.data = malloc(keydata.size);
  if (!keyblock.keyvalue.data)
    return MKEY_ERR_NO_MEM;
  memcpy(keyblock.keyvalue.data, keydata.data, keydata.size);

  /* begin critical section */
  err = pthread_rwlock_wrlock(&tag->lock);
  if (err) {
    free(keyblock.keyvalue.data);
    return err;
  }

  if (tag->meta_state == MKEY_MSTATE_LOADING) {
    pthread_rwlock_unlock(&tag->lock);
    free(keyblock.keyvalue.data);
    return MKEY_ERR_LOADING;
  }

  if (tag->meta_state == MKEY_MSTATE_SEALED) {
    pthread_rwlock_unlock(&tag->lock);
    free(keyblock.keyvalue.data);
    return MKEY_ERR_SEALED;
  }

  if (tag->meta_state == MKEY_MSTATE_OPEN)
    free(tag->meta_key.keyvalue.data);

  tag->meta_state = MKEY_MSTATE_OPEN;
  tag->meta_kvno = intargs[0];
  tag->meta_enctype = intargs[1];
  tag->meta_key = keyblock;
  if (tag->challenge.length) {
    memset(tag->challenge.data, 0, tag->challenge.length);
    free(tag->challenge.data);
    memset(&tag->challenge.data, 0, sizeof(tag->challenge.data));
  }

  err = pthread_rwlock_unlock(&tag->lock);
  if (err) return err;
  /* end critical section */

  if (krb5_enctype_to_string(ctx, intargs[1], &etypestr)) {
    syslog(LOG_INFO, "%s: set metakey kvno %d (%d)",
           tagname, intargs[0], intargs[1]);
  } else {
    syslog(LOG_INFO, "%s: set metakey kvno %d (%s)",
           tagname, intargs[0], etypestr);
    free(etypestr);
  }
  return _mkey_encode(repbuf, replen, cookie, 0, 0, 0, 0, 0);
}


static MKey_Error op_string_to_etype(MKey_Integer cookie, char *reqbuf, int reqlen,
                                     char *repbuf, int *replen)
{
  MKey_Integer enctype;
  MKey_Error err;
  krb5_context ctx;
  krb5_enctype etype;
  char *str;

  err = _mkey_decode(reqbuf, reqlen, 0, 0, 0, 0, 0, &str);
  if (err) return err;

  err = context_setup(&ctx);
  if (err) return err;

  err = krb5_string_to_enctype(ctx, str, &etype);
  if (err) return err;

  enctype = etype;
  err = _mkey_encode(repbuf, replen, cookie, 0, 1, &enctype, 0, 0);
  return err;
}


static MKey_Error op_etype_to_string(MKey_Integer cookie, char *reqbuf, int reqlen,
                                     char *repbuf, int *replen)
{
  MKey_Integer enctype;
  MKey_Error err;
  krb5_context ctx;
  char *str;

  err = _mkey_decode(reqbuf, reqlen, 1, &enctype, 0, 0, 0, 0);
  if (err) return err;

  err = context_setup(&ctx);
  if (err) return err;

  err = krb5_enctype_to_string(ctx, enctype, &str);
  if (err) return err;

  err = _mkey_encode(repbuf, replen, cookie, 0, 0, 0, 0, str);
  free(str);
  return err;
}


static MKey_Error op_store_keys(MKey_Integer cookie, char *reqbuf, int reqlen,
                                char *repbuf, int *replen)
{
  MKey_Error err;
  struct taginfo *tag;
  struct keyinfo *key;
  krb5_context ctx;
  krb5_crypto crypto;
  krb5_keytab_entry ktent;
  krb5_keytab kt;
  char *ktname, *filename1, *filename2;
  char *tagname, rbuf[128];
  int l, count;

  err = _mkey_decode(reqbuf, reqlen, 0, 0, 0, 0, 0, &tagname);
  if (err) return err;

  err = find_tag(tagname, &tag, 0);
  if (err) return err;

  err = context_setup(&ctx);
  if (err) return err;

  l = strlen(keytab_dir) + strlen(tagname) + 32;
  ktname = malloc(l);
  if (!ktname) return MKEY_ERR_NO_MEM;
  filename2 = malloc(l);
  if (!filename2) {
    free(ktname);
    return MKEY_ERR_NO_MEM;
  }
  sprintf(ktname,  "FILE:%s/mkeytab.%s.NEW", keytab_dir, tagname);
  sprintf(filename2, "%s/mkeytab.%s",         keytab_dir, tagname);
  filename1 = ktname + 5;

  /* begin critical section */
  err = pthread_rwlock_wrlock(&tag->lock);
  if (err) {
    free(ktname);
    free(filename2);
    return err;
  }

  if (tag->meta_state == MKEY_MSTATE_LOADING) {
    pthread_rwlock_unlock(&tag->lock);
    free(ktname);
    free(filename2);
    return MKEY_ERR_LOADING;
  }

  if (tag->meta_state == MKEY_MSTATE_SEALED) {
    pthread_rwlock_unlock(&tag->lock);
    free(ktname);
    free(filename2);
    return MKEY_ERR_SEALED;
  }

  if (tag->meta_state == MKEY_MSTATE_NEW) {
    pthread_rwlock_unlock(&tag->lock);
    free(ktname);
    free(filename2);
    return MKEY_ERR_NO_META;
  }

  err = krb5_crypto_init(ctx, &tag->meta_key, tag->meta_enctype, &crypto);
  if (err) {
    pthread_rwlock_unlock(&tag->lock);
    free(ktname);
    free(filename2);
    return err;
  }

  /* generate a challenge if needed */
  if (!tag->challenge.length) {
    krb5_generate_random_block(rbuf, sizeof(rbuf));
    err = krb5_encrypt(ctx, crypto, MKEY_KU_CHAL, rbuf, sizeof(rbuf),
                       &tag->challenge);
    if (err) {
      memset(&tag->challenge, 0, sizeof(tag->challenge));
      pthread_rwlock_unlock(&tag->lock);
      free(ktname);
      free(filename2);
      return err;
    }
  }

  /* open the keytab */
  unlink(filename1);
  err = krb5_kt_resolve(ctx, ktname, &kt);
  if (err) {
    krb5_crypto_destroy(ctx, crypto);
    pthread_rwlock_unlock(&tag->lock);
    free(ktname);
    free(filename2);
    return err;
  }

  /* write the challenge */
  memset(&ktent, 0, sizeof(ktent));
  err = krb5_make_principal(ctx, &ktent.principal, "MKEY:CHAL", tagname, 0);
  if (err) {
    krb5_kt_close(ctx, kt);
    unlink(filename1);
    pthread_rwlock_unlock(&tag->lock);
    krb5_crypto_destroy(ctx, crypto);
    free(ktname);
    free(filename2);
    return err;
  }
  ktent.vno               = tag->meta_kvno;
  ktent.keyblock.keytype  = tag->meta_enctype;
  ktent.keyblock.keyvalue = tag->challenge;
  err = krb5_kt_add_entry(ctx, kt, &ktent);
  if (err) {
    krb5_kt_close(ctx, kt);
    unlink(filename1);
    pthread_rwlock_unlock(&tag->lock);
    krb5_crypto_destroy(ctx, crypto);
    krb5_free_principal(ctx, ktent.principal);
    free(ktname);
    free(filename2);
    return err;
  }
  krb5_free_principal(ctx, ktent.principal);

  memset(&ktent, 0, sizeof(ktent));
  err = krb5_make_principal(ctx, &ktent.principal, "MKEY:KEY", tagname, 0);
  if (err) {
    krb5_kt_close(ctx, kt);
    unlink(filename1);
    pthread_rwlock_unlock(&tag->lock);
    krb5_crypto_destroy(ctx, crypto);
    free(ktname);
    free(filename2);
    return err;
  }
  count = 0;
  for (key = tag->keys; key; key = key->next) {
    /* begin critical section on key */
    err = pthread_mutex_lock(&key->mutex);
    if (err) {
      krb5_kt_close(ctx, kt);
      unlink(filename1);
      pthread_rwlock_unlock(&tag->lock);
      krb5_crypto_destroy(ctx, crypto);
      krb5_free_principal(ctx, ktent.principal);
      free(ktname);
      free(filename2);
      return err;
    }

    if (!key->enctype) {
      pthread_mutex_unlock(&key->mutex);
      continue;
    }

    count++;
    ktent.vno = key->kvno;
    ktent.keyblock.keytype  = key->enctype;
    memset(&ktent.keyblock.keyvalue, 0, sizeof(ktent.keyblock.keyvalue));
    err = krb5_encrypt(ctx, crypto, MKEY_KU_META,
                       key->key.keyvalue.data, key->key.keyvalue.length,
                       &ktent.keyblock.keyvalue);
    if (err) {
      pthread_mutex_unlock(&key->mutex);
      krb5_kt_close(ctx, kt);
      unlink(filename1);
      pthread_rwlock_unlock(&tag->lock);
      krb5_crypto_destroy(ctx, crypto);
      krb5_free_principal(ctx, ktent.principal);
      free(ktname);
      free(filename2);
      return err;
    }

    err = pthread_mutex_unlock(&key->mutex);
    if (err) {
      krb5_kt_close(ctx, kt);
      unlink(filename1);
      pthread_rwlock_unlock(&tag->lock);
      krb5_crypto_destroy(ctx, crypto);
      free(ktent.keyblock.keyvalue.data);
      krb5_free_principal(ctx, ktent.principal);
      free(ktname);
      free(filename2);
      return err;
    }
    /* end critical section on key */

    /* write the keytab entry */
    err = krb5_kt_add_entry(ctx, kt, &ktent);
    free(ktent.keyblock.keyvalue.data);
    if (err) {
      krb5_kt_close(ctx, kt);
      unlink(filename1);
      pthread_rwlock_unlock(&tag->lock);
      krb5_crypto_destroy(ctx, crypto);
      krb5_free_principal(ctx, ktent.principal);
      free(ktname);
      free(filename2);
      return err;
    }
  }

  krb5_free_principal(ctx, ktent.principal);

  /* close the keytab */
  err = krb5_kt_close(ctx, kt);
  if (err) {
    unlink(filename1);
    pthread_rwlock_unlock(&tag->lock);
    free(ktname);
    free(filename2);
    return err;
  }

  /* rename it into place */
  err = rename(filename1, filename2);
  free(ktname);
  free(filename2);
  if (err) {
    pthread_rwlock_unlock(&tag->lock);
    return err;
  }

  err = pthread_rwlock_unlock(&tag->lock);
  if (err) return err;
  /* end critical section */

  syslog(LOG_INFO, "%s: stored %d keys", tagname, count);
  return _mkey_encode(repbuf, replen, cookie, 0, 0, 0, 0, 0);
}


static MKey_Error op_load_keys(MKey_Integer cookie, char *reqbuf, int reqlen,
                               char *repbuf, int *replen)
{
  MKey_Error err, err2;
  struct taginfo *tag;
  struct keyinfo *key;
  krb5_context ctx;
  krb5_keytab kt;
  krb5_kt_cursor cursor;
  krb5_keytab_entry ktent;
  krb5_data keydata;
  krb5_keytype keytype;
  char *ktname, *tagname;
  const char *c0, *c1, *realm;
  int l, is_chal, count;

  err = _mkey_decode(reqbuf, reqlen, 0, 0, 0, 0, 0, &tagname);
  if (err) return err;

  err = find_tag(tagname, &tag, 1);
  if (err) return err;

  err = context_setup(&ctx);
  if (err) return err;

  l = strlen(keytab_dir) + strlen(tagname) + 32;
  ktname = malloc(l);
  if (!ktname) return MKEY_ERR_NO_MEM;
  sprintf(ktname,  "FILE:%s/mkeytab.%s", keytab_dir, tagname);

  err = krb5_kt_resolve(ctx, ktname, &kt);
  if (err) {
    free(ktname);
    return err;
  }

  /* begin critical section */
  err = pthread_rwlock_wrlock(&tag->lock);
  if (err) {
    krb5_kt_close(ctx, kt);
    free(ktname);
    return err;
  }

  if (tag->meta_state == MKEY_MSTATE_LOADING) {
    pthread_rwlock_unlock(&tag->lock);
    krb5_kt_close(ctx, kt);
    free(ktname);
    return MKEY_ERR_LOADING;
  }

  if (tag->meta_state == MKEY_MSTATE_SEALED) {
    pthread_rwlock_unlock(&tag->lock);
    krb5_kt_close(ctx, kt);
    free(ktname);
    return MKEY_ERR_SEALED;
  }

  tag->meta_state = MKEY_MSTATE_LOADING;

  err = pthread_rwlock_unlock(&tag->lock);
  if (err) {
    krb5_kt_close(ctx, kt);
    free(ktname);
    return err;
  }
  /* end critical section */

  err = krb5_kt_start_seq_get(ctx, kt, &cursor);
  if (err) goto fail;

  count = 0;
  while (!krb5_kt_next_entry(ctx, kt, &ktent, &cursor)) {
    c0 = krb5_principal_get_comp_string(ctx, ktent.principal, 0);
    c1 = krb5_principal_get_comp_string(ctx, ktent.principal, 1);
    realm = krb5_principal_get_realm(ctx, ktent.principal);
    if (!realm || !c0 || c1 || strcmp(c0, tagname)) {
      /* doesn't look like it's for us */
      krb5_kt_free_entry(ctx, &ktent);
      continue;
    }

    if      (!strcmp(realm, "MKEY:CHAL")) is_chal = 1;
    else if (!strcmp(realm, "MKEY:KEY"))  is_chal = 0;
    else {
      /* doesn't look like it's for us */
      krb5_kt_free_entry(ctx, &ktent);
      continue;
    }

    err = krb5_enctype_to_keytype(ctx, ktent.keyblock.keytype, &keytype);
    if (err) {
      krb5_kt_free_entry(ctx, &ktent);
      break;
    }

    keydata.length = ktent.keyblock.keyvalue.length;
    keydata.data = malloc(keydata.length);
    if (!keydata.data) {
      krb5_kt_free_entry(ctx, &ktent);
      err = MKEY_ERR_NO_MEM;
      break;
    }
    memcpy(keydata.data, ktent.keyblock.keyvalue.data, keydata.length);

    if (is_chal) {
      /* the challenge */

      /* begin critical section */
      err = pthread_rwlock_wrlock(&tag->lock);
      if (err) {
        free(keydata.data);
        krb5_kt_free_entry(ctx, &ktent);
        break;
      }

      tag->meta_kvno    = ktent.vno;
      tag->meta_enctype = ktent.keyblock.keytype;
      if (tag->challenge.data) free(tag->challenge.data);
      tag->challenge = keydata;

      err = pthread_rwlock_unlock(&tag->lock);
      if (err) {
        krb5_kt_free_entry(ctx, &ktent);
        break;
      }
      /* end critical section */

    } else {
      /* it's a key */
      count++;

      err = find_key(tag, ktent.vno, &key, 1);
      if (err) {
        free(keydata.data);
        krb5_kt_free_entry(ctx, &ktent);
        break;
      }

      /* begin critical section */
      err = pthread_mutex_lock(&key->mutex);
      if (err) {
        free(keydata.data);
        krb5_kt_free_entry(ctx, &ktent);
        break;
      }

      if (key->enctype) {
        /* replace existing values */
        memset(key->key.keyvalue.data, 0, key->key.keyvalue.length);
        free(key->key.keyvalue.data);
        if (key->crypto) {
          krb5_crypto_destroy(ctx, key->crypto);
          key->crypto = 0;
        }
      }

      key->sealed       = 1;
      key->enctype      = ktent.keyblock.keytype;
      key->key.keytype  = keytype;
      key->key.keyvalue = keydata;

      err = pthread_mutex_unlock(&key->mutex);
      if (err) {
        krb5_kt_free_entry(ctx, &ktent);
        break;
      }
      /* end critical section */
    }

    krb5_kt_free_entry(ctx, &ktent);
  }
  krb5_kt_end_seq_get(ctx, kt, &cursor);

fail:
  err2 = krb5_kt_close(ctx, kt);
  if (!err) err = err2;
  free(ktname);

  /* begin critical section */
  err2 = pthread_rwlock_wrlock(&tag->lock);
  if (err2) return err ? err : err2;

  tag->meta_state = MKEY_MSTATE_SEALED;

  err2 = pthread_rwlock_unlock(&tag->lock);
  if (!err) err = err2;
  /* end critical section */

  if (err) return err;

  syslog(LOG_INFO, "%s: loaded %d keys", tagname, count);
  return _mkey_encode(repbuf, replen, cookie, 0, 0, 0, 0, 0);
}



static void proc_request(char *reqbuf, int reqlen, char *repbuf, int *replen)
{
  MKey_Integer cookie, reqid;
  MKey_Error err;

  cookie = 0;
  err = _mkey_decode_header(reqbuf, reqlen, &cookie, &reqid);
  if (err) goto fail;

  if (reqid < 0 || reqid > n_operations - 1 || !operations[reqid])
    err = MKEY_ERR_UNKNOWN_REQ;
  else
    err = (operations[reqid])(cookie, reqbuf, reqlen, repbuf, replen);

fail:
  if (err) _mkey_encode(repbuf, replen, cookie, err, 0, 0, 0, 0);
}

#ifdef USE_DOORS
static void handle_door_request(void *cookie, char *argp, size_t arg_size,
                                door_desc_t *dp, size_t ndesc)
{
  char repbuf[MKEY_MAXSIZE + 1];
  int replen;

  if (argp == DOOR_UNREF_DATA) {
    /* time to shut down! */
    exit(0);
  }
  replen = MKEY_MAXSIZE;
  proc_request(argp, arg_size, repbuf, &replen);
  door_return(repbuf, replen, 0, 0);
}

static void mainloop(void)
{
  int doorfd, err;

  err = pthread_mutex_lock(&exit_mutex);
  if (err) {
    syslog(LOG_ERR, "unable to acquire exit mutex: %s\n", strerror(errno));
    exit(1);
  }

  unlink(sock_name);
  doorfd = open(sock_name, O_CREAT|O_RDWR, 0600);
  if (doorfd < 0) {
    syslog(LOG_ERR, "create %s: %s", sock_name, strerror(errno));
    exit(1);
  }
  fchmod(doorfd, 0600);
  close(doorfd);

  doorfd = door_create(handle_door_request, NULL, DOOR_UNREF);
  if (doorfd < 0) {
    syslog(LOG_ERR, "door_create: %s", strerror(errno));
    exit(1);
  }
  if (fattach(doorfd, sock_name) < 0) {
    syslog(LOG_ERR, "fattach %s: %s", sock_name, strerror(errno));
    exit(1);
  }

  for (;;) {
    pthread_cond_wait(&exit_cv, &exit_mutex);
    door_revoke(doorfd);
  }
}

#else /* !USE_DOORS */

#error write some code

#endif /* USE_DOORS */


int main(int argc, char **argv)
{
  struct rlimit rl;
  char *argv0;
  int err;

  argv0 = strrchr(argv[0], '/');
  argv0 = argv0 ? argv0 + 1 : argv[0];

  if (argc > 1) sock_name = argv[1];
  if (argc > 2) keytab_dir = argv[2];

  openlog(argv0, LOG_PID, MKEY_FACILITY);
  syslog(LOG_INFO, "mkeyd %s", "$Revision$");
  err = mlockall(MCL_CURRENT | MCL_FUTURE);
  if (err) {
    syslog(LOG_ERR, "mlockall: %s", strerror(errno));
    exit(1);
  }
  memset(&rl, 0, sizeof(rl));
  err = setrlimit(RLIMIT_CORE, &rl);
  if (err) {
    syslog(LOG_ERR, "setrlimit: %s", strerror(errno));
    exit(1);
  }
  err = pthread_rwlock_init(&masterlock, 0);
  if (err) {
    syslog(LOG_ERR, "master lock init failed: %s", strerror(err));
    exit(1);
  }
  err = pthread_key_create(&contextkey, context_destruct);
  if (err) {
    syslog(LOG_ERR, "context key init failed: %s", strerror(err));
    exit(1);
  }
  err = pthread_mutex_init(&exit_mutex, 0);
  if (err) {
    syslog(LOG_ERR, "exit mutex init failed: %s", strerror(err));
    exit(1);
  }
  err = pthread_cond_init(&exit_cv, 0);
  if (err) {
    syslog(LOG_ERR, "exit CV init failed: %s", strerror(err));
    exit(1);
  }

  mainloop();
}
