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
 * mkey library implementation
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <door.h>
#include <errno.h>

#include "mkey_err.h"
#include "libmkey.h"
#include "mkey.h"


static char req_buf[MKEY_MAXSIZE + 1];
static char rep_buf[MKEY_MAXSIZE + 1];
static MKey_Integer cookie = 0;
static int mkeyd_sock = -1;


static void mkheader(MKey_Integer reqid)
{
  if (!cookie) {
    srand(time(0) ^ getpid());
    cookie = rand();
  }
  cookie++;
  memcpy(req_buf + 0, &cookie, 4);
  memcpy(req_buf + 4, &reqid, 4);
}

static MKey_Error do_request(int reqlen, int *replen, char **repptr)
{
  MKey_Integer rcookie;
  MKey_Error err, lasterr;
  door_arg_t arg;
  int try;

  lasterr = MKEY_ERR_TIMEOUT;
  for (try = 0; try < 3;) {
#ifdef USE_DOORS
    if (mkeyd_sock < 0) {
      mkeyd_sock = open(MKEY_DOOR, O_RDONLY);
      if (mkeyd_sock < 0) return errno;
    }

    arg.data_ptr = req_buf;
    arg.data_size = reqlen;
    arg.desc_ptr = 0;
    arg.desc_num = 0;
    arg.rbuf = rep_buf;
    arg.rsize = MKEY_MAXSIZE;

    if (door_call(mkeyd_sock, &arg)) {
      switch (errno) {
        default:        return errno;
        case EOVERFLOW: return MKEY_ERR_TOO_BIG;
        case EINTR:     continue;
        case EAGAIN:
          try++;
          close(mkeyd_sock);
          mkeyd_sock = -1;
          continue;
      }
    }
    if (arg.rbuf != rep_buf) {
      munmap(arg.rbuf, arg.rsize);
      return MKEY_ERR_TOO_BIG;
    }

    *repptr = arg.data_ptr;
    *replen = arg.data_size;
#else /* !USE_DOORS */
#error write some code
#endif /* USE_DOORS */

    try++;

    if (*replen < MKEY_HDRSIZE) {
      lasterr = MKEY_ERR_REP_FORMAT;
      continue;
    }

    memcpy(&rcookie, *repptr, 4);
    if (rcookie != cookie) {
      lasterr = MKEY_ERR_REP_COOKIE;
      continue;
    }

    memcpy(&err, *repptr + 4, 4);
    if (err) return err;

    if (*replen > MKEY_MAXSIZE)
      return MKEY_ERR_TOO_BIG;
    (*repptr)[*replen] = 0;
    return 0;
  }
  return lasterr;
}


MKey_Error mkey_encrypt(char *tag, MKey_Integer kvno, 
                        MKey_DataBlock *in, MKey_DataBlock *out)
{
  MKey_Error err;
  MKey_Integer outsize;
  int reqlen, replen;
  char *repptr;

  reqlen = MKEY_HDRSIZE + 8 + in->size + strlen(tag) + 1;
  if (reqlen > MKEY_MAXSIZE)
    return MKEY_ERR_TOO_BIG;

  mkheader(MKEY_OP_ENCRYPT);
  memcpy(req_buf + MKEY_HDRSIZE, &kvno, 4);
  memcpy(req_buf + MKEY_HDRSIZE + 4, &(in->size), 4);
  memcpy(req_buf + MKEY_HDRSIZE + 8, in->data, in->size);
  strcpy(req_buf + MKEY_HDRSIZE + 8 + in->size, tag);

  err = do_request(reqlen, &replen, &repptr);
  if (err) return err;

  if (replen < MKEY_HDRSIZE + 4)
    return MKEY_ERR_REP_FORMAT;
  memcpy(&outsize, repptr + MKEY_HDRSIZE, 4);
  if (replen != MKEY_HDRSIZE + 4 + outsize)
    return MKEY_ERR_REP_FORMAT;
  if (outsize > out->size)
    return MKEY_ERR_OVERFLOW;
  memcpy(out->data, repptr + MKEY_HDRSIZE + 4, outsize);
  out->size = outsize;
  return 0;
}


MKey_Error mkey_decrypt(char *tag, MKey_Integer kvno, 
                        MKey_DataBlock *in, MKey_DataBlock *out)
{
  MKey_Error err;
  MKey_Integer outsize;
  int reqlen, replen;
  char *repptr;

  reqlen = MKEY_HDRSIZE + 8 + in->size + strlen(tag) + 1;
  if (reqlen > MKEY_MAXSIZE)
    return MKEY_ERR_TOO_BIG;

  mkheader(MKEY_OP_DECRYPT);
  memcpy(req_buf + MKEY_HDRSIZE, &kvno, 4);
  memcpy(req_buf + MKEY_HDRSIZE + 4, &(in->size), 4);
  memcpy(req_buf + MKEY_HDRSIZE + 8, in->data, in->size);
  strcpy(req_buf + MKEY_HDRSIZE + 8 + in->size, tag);

  err = do_request(reqlen, &replen, &repptr);
  if (err) return err;

  if (replen < MKEY_HDRSIZE + 4)
    return MKEY_ERR_REP_FORMAT;
  memcpy(&outsize, repptr + MKEY_HDRSIZE, 4);
  if (replen != MKEY_HDRSIZE + 4 + outsize)
    return MKEY_ERR_REP_FORMAT;
  if (outsize > out->size)
    return MKEY_ERR_OVERFLOW;
  memcpy(out->data, repptr + MKEY_HDRSIZE + 4, outsize);
  out->size = outsize;
  return 0;
}


MKey_Error mkey_add_key(char *tag, MKey_Integer kvno,
                        MKey_Integer enctype, MKey_DataBlock *key)
{
  MKey_Error err;
  int reqlen, replen;
  char *repptr;

  reqlen = MKEY_HDRSIZE + 12 + key->size + strlen(tag) + 1;
  if (reqlen > MKEY_MAXSIZE)
    return MKEY_ERR_TOO_BIG;

  mkheader(MKEY_OP_ADD_KEY);
  memcpy(req_buf + MKEY_HDRSIZE,      &kvno, 4);
  memcpy(req_buf + MKEY_HDRSIZE + 4,  &enctype, 4);
  memcpy(req_buf + MKEY_HDRSIZE + 8,  &(key->size), 4);
  memcpy(req_buf + MKEY_HDRSIZE + 12, key->data, key->size);
  strcpy(req_buf + MKEY_HDRSIZE + 12 + key->size, tag);

  err = do_request(reqlen, &replen, &repptr);
  if (err) return err;

  if (replen != MKEY_HDRSIZE)
    return MKEY_ERR_REP_FORMAT;
  return 0;
}


MKey_Error mkey_remove_key(char *tag, MKey_Integer kvno)
{
  MKey_Error err;
  int reqlen, replen;
  char *repptr;

  reqlen = MKEY_HDRSIZE + 4 + strlen(tag) + 1;
  if (reqlen > MKEY_MAXSIZE)
    return MKEY_ERR_TOO_BIG;

  mkheader(MKEY_OP_REMOVE_KEY);
  memcpy(req_buf + MKEY_HDRSIZE,     &kvno, 4);
  strcpy(req_buf + MKEY_HDRSIZE + 4, tag);

  err = do_request(reqlen, &replen, &repptr);
  if (err) return err;

  if (replen != MKEY_HDRSIZE)
    return MKEY_ERR_REP_FORMAT;
  return 0;
}


MKey_Error mkey_verify_key(char *tag, MKey_Integer kvno)
{
  MKey_Error err;
  int reqlen, replen;
  char *repptr;

  reqlen = MKEY_HDRSIZE + 4 + strlen(tag) + 1;
  if (reqlen > MKEY_MAXSIZE)
    return MKEY_ERR_TOO_BIG;

  mkheader(MKEY_OP_VERIFY_KEY);
  memcpy(req_buf + MKEY_HDRSIZE,     &kvno, 4);
  strcpy(req_buf + MKEY_HDRSIZE + 4, tag);

  err = do_request(reqlen, &replen, &repptr);
  if (err) return err;

  if (replen != MKEY_HDRSIZE)
    return MKEY_ERR_REP_FORMAT;
  return 0;
}


MKey_Error mkey_list_keys(char *tag, MKey_Integer *nkeys, MKey_KeyInfo *keys)
{
  MKey_Error err;
  MKey_Integer onkeys;
  int reqlen, replen, i;
  char *repptr;

  reqlen = MKEY_HDRSIZE + strlen(tag) + 1;
  if (reqlen > MKEY_MAXSIZE)
    return MKEY_ERR_TOO_BIG;

  mkheader(MKEY_OP_LIST_KEYS);
  strcpy(req_buf + MKEY_HDRSIZE, tag);

  err = do_request(reqlen, &replen, &repptr);
  if (err) return err;

  if (replen < MKEY_HDRSIZE + 4)
    return MKEY_ERR_REP_FORMAT;
  memcpy(&onkeys, repptr + MKEY_HDRSIZE, 4);
  if (replen != MKEY_HDRSIZE + 4 + onkeys * 8)
    return MKEY_ERR_REP_FORMAT;
  if (onkeys > *nkeys)
    return MKEY_ERR_OVERFLOW;
  for (i = 0; i < onkeys; i++) {
    memcpy(&keys[i].kvno,    repptr + MKEY_HDRSIZE + 4 + 2*i, 4);
    memcpy(&keys[i].enctype, repptr + MKEY_HDRSIZE + 4 + 2*i + 4, 4);
  }
  *nkeys = onkeys;
  return 0;
}


MKey_Error mkey_list_tag(MKey_Integer tagid, char *tag, int bufsize)
{
  MKey_Error err;
  int reqlen, replen;
  char *repptr;

  reqlen = MKEY_HDRSIZE + 4;
  if (reqlen > MKEY_MAXSIZE)
    return MKEY_ERR_TOO_BIG;

  mkheader(MKEY_OP_LIST_TAG);
  memcpy(req_buf + MKEY_HDRSIZE, &tagid, 4);

  err = do_request(reqlen, &replen, &repptr);
  if (err) return err;

  if (replen < MKEY_HDRSIZE)
    return MKEY_ERR_REP_FORMAT;
  if (replen - MKEY_HDRSIZE + 1 > bufsize)
    return MKEY_ERR_OVERFLOW;
  strcpy(tag, repptr + MKEY_HDRSIZE);
  return 0;
}


MKey_Error mkey_shutdown(void)
{
  MKey_Error err;
  int reqlen, replen;
  char *repptr;

  reqlen = MKEY_HDRSIZE;
  mkheader(MKEY_OP_SHUTDOWN);
  err = do_request(reqlen, &replen, &repptr);
  if (err) return err;
  if (replen != MKEY_HDRSIZE)
    return MKEY_ERR_REP_FORMAT;
  return 0;
}
