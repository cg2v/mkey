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
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <fcntl.h>
#include <stropts.h>
#include <pthread.h>
#include <door.h>

#include <krb5.h>
#include <krb5_err.h>
#include <hdb.h>

#include "mkey.h"
#include "mkey_err.h"

typedef int32_t (*opfunc)    (char *, int, char *, int *);
static int32_t op_encrypt    (char *, int, char *, int *);
static int32_t op_decrypt    (char *, int, char *, int *);
static int32_t op_add_key    (char *, int, char *, int *);
static int32_t op_remove_key (char *, int, char *, int *);
static int32_t op_list_keys  (char *, int, char *, int *);
static int32_t op_list_tag   (char *, int, char *, int *);
static int32_t op_shutdown   (char *, int, char *, int *);

static opfunc operations[] = {
  op_encrypt,    /* MKEY_OP_ENCRYPT    */
  op_decrypt,    /* MKEY_OP_DECRYPT    */
  op_add_key,    /* MKEY_OP_ADD_KEY    */
  op_remove_key, /* MKEY_OP_REMOVE_KEY */
  op_list_keys,  /* MKEY_OP_LIST_KEYS  */
  op_list_tag,   /* MKEY_OP_LIST_TAG   */
  op_shutdown,   /* MKEY_OP_SHUTDOWN   */
};
#define n_operations (sizeof(operations) / sizeof(operations[0]))

struct keyinfo {
  struct keyinfo *next;
  int kvno;
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
};

static struct taginfo *taglist;
static int max_slot;
static pthread_rwlock_t masterlock;
static pthread_key_t contextkey;


static int32_t context_setup(krb5_context *ctx)
{
  int err;

  *ctx = pthread_getspecific(contextkey);
  if (*ctx) return 0;

  err = krb5_init_context(ctx);
  if (err) return err;
  return pthread_setspecific(contextkey, ctx);
}

static void context_destruct(void * ctx)
{
  krb5_free_context(ctx);
  pthread_setspecific(contextkey, 0);
}


static int32_t find_tag(char *name, struct taginfo **rtag, int create)
{
  struct taginfo *tag;
  int err;

  if (create)
    err = pthread_rwlock_wrlock(&masterlock);
  else
    err = pthread_rwlock_rdlock(&masterlock);
  if (err) return err;

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

static int32_t find_tag_slot(int slot, struct taginfo **rtag)
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

static int32_t find_key(struct taginfo *tag, int kvno,
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




static int32_t encrypt_decrypt(char *reqbuf, int reqlen, char *repbuf, int *replen, int dir)
{
  int32_t kvno, textsize, rtextsize, err;
  char *tagname, *text;
  struct taginfo *tag;
  struct keyinfo *key;
  krb5_context ctx;
  krb5_data res;

  if (reqlen < MKEY_HDRSIZE + 8)
    return MKEY_ERR_REQ_FORMAT;
  memcpy(&kvno, reqbuf, 4);
  memcpy(&textsize, reqbuf + 4, 4);
  if (reqlen < MKEY_HDRSIZE + 8 + textsize + 1)
    return MKEY_ERR_REQ_FORMAT;
  text = reqbuf + MKEY_HDRSIZE + 8;
  tagname = reqbuf + MKEY_HDRSIZE + 8 + textsize;
  reqbuf[reqlen - 1] = 0;

  err = find_tag(tagname, &tag, 0);
  if (err) return err;
  err = find_key(tag, kvno, &key, 0);
  if (err) return err;

  err = context_setup(&ctx);
  if (err) return err;

  /* begin critical section */
  err = pthread_mutex_lock(&key->mutex);
  if (err) return err;

  err = MKEY_ERR_NO_KEY;
  if (!key->enctype
  ||  (err = krb5_crypto_init(ctx, &key->key, key->enctype, &key->crypto))
  ||  (err = dir ? krb5_encrypt(ctx, key->crypto, HDB_KU_MKEY, text, textsize, &res)
                 : krb5_encrypt(ctx, key->crypto, HDB_KU_MKEY, text, textsize, &res))) {
    pthread_mutex_unlock(&key->mutex);
    return err;
  }

  err = pthread_mutex_unlock(&key->mutex);
  if (err) {
    free(res.data);
    return err;
  }
  /* end critical section */

  rtextsize = res.length;
  if (MKEY_HDRSIZE + 4 + rtextsize > MKEY_MAXSIZE)
    return MKEY_ERR_TOO_BIG;
  *replen = MKEY_HDRSIZE + 4 + rtextsize;
  memcpy(repbuf + MKEY_HDRSIZE, &rtextsize, 4);
  memcpy(repbuf + MKEY_HDRSIZE + 4, res.data, res.length);
  free(res.data);

  return 0;
}

static int32_t op_encrypt(char *reqbuf, int reqlen, char *repbuf, int *replen)
{
  return encrypt_decrypt(reqbuf, reqlen, repbuf, replen, 1);
}

static int32_t op_decrypt(char *reqbuf, int reqlen, char *repbuf, int *replen)
{
  return encrypt_decrypt(reqbuf, reqlen, repbuf, replen, 0);
}


static int32_t op_add_key(char *reqbuf, int reqlen, char *repbuf, int *replen)
{
  int32_t kvno, enctype, keysize, err;
  char *tagname, *keydata;
  struct taginfo *tag;
  struct keyinfo *key;
  krb5_context ctx;
  krb5_keytype keytype;

  if (reqlen < MKEY_HDRSIZE + 12)
    return MKEY_ERR_REQ_FORMAT;
  memcpy(&kvno, reqbuf, 4);
  memcpy(&enctype, reqbuf + 4, 4);
  memcpy(&keysize, reqbuf + 8, 4);
  if (reqlen < MKEY_HDRSIZE + 12 + keysize + 1)
    return MKEY_ERR_REQ_FORMAT;
  keydata = reqbuf + MKEY_HDRSIZE + 12;
  tagname = reqbuf + MKEY_HDRSIZE + 12 + keysize;
  reqbuf[reqlen - 1] = 0;

  err = find_tag(tagname, &tag, 1);
  if (err) return err;
  err = find_key(tag, kvno, &key, 1);
  if (err) return err;

  err = context_setup(&ctx);
  if (err) return err;

  err = krb5_enctype_to_keytype(ctx, enctype, &keytype);
  if (err) return err;

  /* begin critical section */
  err = pthread_mutex_lock(&key->mutex);
  if (err) return err;

  if (key->enctype) {
    pthread_mutex_unlock(&key->mutex);
    return MKEY_ERR_EXIST;
  }

  key->key.keyvalue.data = malloc(keysize);
  if (!key->key.keyvalue.data) {
    pthread_mutex_unlock(&key->mutex);
    return MKEY_ERR_NO_MEM;
  }

  key->enctype = enctype;
  key->key.keytype = keytype;
  key->key.keyvalue.length = keysize;
  memcpy(key->key.keyvalue.data, keydata, keysize);

  err = pthread_mutex_unlock(&key->mutex);
  if (err) return err;
  /* end critical section */

  *replen = MKEY_HDRSIZE;
  return 0;
}


static int32_t op_remove_key(char *reqbuf, int reqlen, char *repbuf, int *replen)
{
  int32_t kvno, err;
  char *tagname;
  struct taginfo *tag;
  struct keyinfo *key;
  krb5_context ctx;

  if (reqlen < MKEY_HDRSIZE + 4 + 1)
    return MKEY_ERR_REQ_FORMAT;
  memcpy(&kvno, reqbuf, 4);
  tagname = reqbuf + MKEY_HDRSIZE + 4;
  reqbuf[reqlen - 1] = 0;

  err = find_tag(tagname, &tag, 0);
  if (err) return err;
  err = find_key(tag, kvno, &key, 0);
  if (err) return err;

  err = pthread_mutex_lock(&key->mutex);
  if (err) return err;

  /* begin critical section */
  if (!key->enctype) {
    pthread_mutex_unlock(&key->mutex);
    return MKEY_ERR_NO_KEY;
  }

  free(key->key.keyvalue.data);
  memset(&key->key, 0, sizeof(key->key));
  key->enctype = 0;

  err = pthread_mutex_unlock(&key->mutex);
  if (err) return err;
  /* end critical section */

  *replen = MKEY_HDRSIZE;
  return 0;
}


static int32_t op_list_keys(char *reqbuf, int reqlen, char *repbuf, int *replen)
{
  int32_t count, kvno, enctype, err;
  char *tagname;
  struct taginfo *tag;
  struct keyinfo *key;
  krb5_context ctx;

  if (reqlen < MKEY_HDRSIZE + 1)
    return MKEY_ERR_REQ_FORMAT;
  tagname = reqbuf + MKEY_HDRSIZE;
  reqbuf[reqlen - 1] = 0;

  err = find_tag(tagname, &tag, 0);
  if (err) return err;

  err = pthread_rwlock_rdlock(&tag->lock);
  if (err) return err;

  count = 0;
  *replen = MKEY_HDRSIZE + 4;
  for (key = tag->keys; key; key = key->next) {
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
    if (!enctype) continue;

    if (*replen + 8 > MKEY_MAXSIZE) {
      pthread_rwlock_unlock(&tag->lock);
      return MKEY_ERR_TOO_BIG;
    }
    memcpy(repbuf + *replen,     &kvno,    4);
    memcpy(repbuf + *replen + 4, &enctype, 4);
    *replen += 8;
    count++;
  }

  err = pthread_rwlock_unlock(&tag->lock);
  if (err) return err;

  memcpy(repbuf + MKEY_HDRSIZE, &count, 4);
  return 0;
}


static int32_t op_list_tag(char *reqbuf, int reqlen, char *repbuf, int *replen)
{
  int32_t slot, err;
  struct taginfo *tag;

  if (reqlen != MKEY_HDRSIZE + 4)
    return MKEY_ERR_REQ_FORMAT;
  memcpy(&slot, reqbuf + MKEY_HDRSIZE, 4);

  err = find_tag_slot(slot, &tag);
  if (err) return err;

  if (MKEY_HDRSIZE + strlen(tag->name) + 1 > MKEY_MAXSIZE)
    return MKEY_ERR_TOO_BIG;
  *replen = MKEY_HDRSIZE + strlen(tag->name) + 1;
  strcpy(repbuf + MKEY_HDRSIZE, tag->name);

  return 0;
}


static int32_t op_shutdown(char *reqbuf, int reqlen, char *repbuf, int *replen)
{
  exit(0);
}


static void proc_request(char *reqbuf, int reqlen, char *repbuf, int *replen)
{
  int32_t cookie, reqid;
  int32_t err;

  cookie = 0;
  err = 0;
  if (reqlen < MKEY_HDRSIZE) {
    err = MKEY_ERR_REQ_FORMAT;
    goto fail;
  }
 
  memcpy(&cookie, reqbuf, 4);
  memcpy(&reqid, reqbuf + 4, 4);

  if (reqid < 0 || reqid > n_operations - 1 || !operations[reqid])
    err = MKEY_ERR_UNKNOWN_REQ;
  else
    err = (operations[reqid])(reqbuf, reqlen, repbuf, replen);

fail:
  if (err) *replen = 8;
  memcpy(repbuf, &cookie, 4);
  memcpy(repbuf + 4, &err, 4);
}

/*** DOOR-SPECIFIC CODE STARTS HERE ***/
static void handle_door_request(void *cookie, char *data, size_t datasize,
                                door_desc_t *dp, size_t ndesc)
{
  char repbuf[MKEY_MAXSIZE + 1];
  int replen;

  proc_request(data, datasize, repbuf, &replen);
  door_return(repbuf, replen, 0, 0);
}

static void mainloop(void)
{
  int doorfd;

  doorfd = open(MKEY_SOCKET, O_CREAT|O_RDWR, 0600);
  if (doorfd < 0) {
    syslog(LOG_ERR, "create %s: %m", MKEY_SOCKET);
    exit(1);
  }
  fchmod(doorfd, 0600);
  close(doorfd);

  doorfd = door_create(handle_door_request, NULL, 0);
  if (doorfd < 0) {
    syslog(LOG_ERR, "door_create: %m");
    exit(1);
  }
  if (fattach(doorfd, MKEY_SOCKET) < 0) {
    syslog(LOG_ERR, "fattach %s: %m", MKEY_SOCKET);
    exit(1);
  }

  for (;;) {
    pause();
  }
}
/*** DOOR-SPECIFIC CODE ENDS HERE ***/


int main(int argc, char **argv)
{
  char *argv0;
  int err;

  argv0 = strrchr(argv[0], '/');
  argv0 = argv0 ? argv0 + 1 : argv[0];

  openlog(argv0, LOG_PID, MKEY_FACILITY);
  syslog(LOG_INFO, "mkeyd %s", "$Revision$");
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
  mainloop();
}
