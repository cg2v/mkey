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

typedef MKey_Error (*opfunc)    (MKey_Integer, char *, int, char *, int *);
static MKey_Error op_encrypt    (MKey_Integer, char *, int, char *, int *);
static MKey_Error op_decrypt    (MKey_Integer, char *, int, char *, int *);
static MKey_Error op_add_key    (MKey_Integer, char *, int, char *, int *);
static MKey_Error op_remove_key (MKey_Integer, char *, int, char *, int *);
static MKey_Error op_verify_key (MKey_Integer, char *, int, char *, int *);
static MKey_Error op_list_keys  (MKey_Integer, char *, int, char *, int *);
static MKey_Error op_list_tag   (MKey_Integer, char *, int, char *, int *);
static MKey_Error op_shutdown   (MKey_Integer, char *, int, char *, int *);

static opfunc operations[] = {
  op_encrypt,    /* MKEY_OP_ENCRYPT    */
  op_decrypt,    /* MKEY_OP_DECRYPT    */
  op_add_key,    /* MKEY_OP_ADD_KEY    */
  op_remove_key, /* MKEY_OP_REMOVE_KEY */
  op_list_keys,  /* MKEY_OP_LIST_KEYS  */
  op_list_tag,   /* MKEY_OP_LIST_TAG   */
  op_shutdown,   /* MKEY_OP_SHUTDOWN   */
  op_verify_key, /* MKEY_OP_VERIFY_KEY */
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
  char *tagname;
  struct taginfo *tag;
  struct keyinfo *key;
  krb5_context ctx;
  krb5_keytype keytype;

  err = _mkey_decode(reqbuf, reqlen, 2, intargs, 0, 0, &keydata, &tagname);
  if (err) return err;

  err = find_tag(tagname, &tag, 1);
  if (err) return err;

  err = find_key(tag, intargs[0], &key, 1);
  if (err) return err;

  err = context_setup(&ctx);
  if (err) return err;

  err = krb5_enctype_to_keytype(ctx, intargs[1], &keytype);
  if (err) return err;

  /* begin critical section */
  err = pthread_mutex_lock(&key->mutex);
  if (err) return err;

  if (key->enctype) {
    pthread_mutex_unlock(&key->mutex);
    return MKEY_ERR_EXIST;
  }

  key->key.keyvalue.data = malloc(keydata.size);
  if (!key->key.keyvalue.data) {
    pthread_mutex_unlock(&key->mutex);
    return MKEY_ERR_NO_MEM;
  }

  key->enctype = intargs[1];
  key->key.keytype = keytype;
  key->key.keyvalue.length = keydata.size;
  memcpy(key->key.keyvalue.data, keydata.data, keydata.size);

  err = pthread_mutex_unlock(&key->mutex);
  if (err) return err;
  /* end critical section */

  syslog(LOG_INFO, "added key %s[%d]", tagname, intargs[0]);
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

  syslog(LOG_INFO, "removed key %s[%d]", tagname, kvno);
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
  /* well, this will eat up some stack... */
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

  err = pthread_rwlock_rdlock(&tag->lock);
  if (err) return err;

  i = 1;
  count = 0;
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
    unlink(sock_name);
  }
}

#else /* !USE_DOORS */

#error write some code

#endif /* USE_DOORS */


int main(int argc, char **argv)
{
  char *argv0;
  int err;

  argv0 = strrchr(argv[0], '/');
  argv0 = argv0 ? argv0 + 1 : argv[0];

  if (argc > 1) sock_name = argv[1];

  openlog(argv0, LOG_PID, MKEY_FACILITY);
  syslog(LOG_INFO, "mkeyd %s", "$Revision$");
  err = mlockall(MCL_CURRENT | MCL_FUTURE);
  if (err) {
    syslog(LOG_ERR, "mlockall: %s", strerror(err));
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
