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
static MKey_Integer global_cookie = 0;
static int mkeyd_sock = -1;


static MKey_Integer getcookie()
{
  if (!global_cookie) {
    srand(time(0) ^ getpid());
    global_cookie = rand();
  }
  global_cookie++;
  return global_cookie;
}

static MKey_Error do_request(MKey_Integer cookie, int reqlen,
                             int *replen, char **repptr)
{
  MKey_Integer rcookie;
  MKey_Error err, errcode, lasterr;
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

    err = _mkey_decode_header(*repptr, *replen, &rcookie, &errcode);
    if (err) {
      lasterr = err;
      continue;
    }

    if (rcookie != cookie) {
      lasterr = MKEY_ERR_REP_COOKIE;
      continue;
    }

    return errcode;
  }
  return lasterr;
}


MKey_Error mkey_encrypt(char *tag, MKey_Integer kvno, 
                        MKey_DataBlock *in, MKey_DataBlock *out)
{
  MKey_DataBlock outdata;
  MKey_Integer cookie;
  MKey_Error err;
  int reqlen, replen;
  char *repptr;

  reqlen = MKEY_MAXSIZE;
  cookie = getcookie();
  err = _mkey_encode(req_buf, &reqlen, cookie, MKEY_OP_ENCRYPT,
                     1, &kvno, in, tag);
  if (err) return err;

  err = do_request(cookie, reqlen, &replen, &repptr);
  if (err) return err;

  err = _mkey_decode(repptr, replen, 0, 0, 0, 0, &outdata, 0);
  if (err) return err;

  if (outdata.size > out->size)
    return MKEY_ERR_OVERFLOW;
  memcpy(out->data, outdata.data, outdata.size);
  out->size = outdata.size;

  return 0;
}


MKey_Error mkey_decrypt(char *tag, MKey_Integer kvno, 
                        MKey_DataBlock *in, MKey_DataBlock *out)
{
  MKey_DataBlock outdata;
  MKey_Integer cookie;
  MKey_Error err;
  int reqlen, replen;
  char *repptr;

  reqlen = MKEY_MAXSIZE;
  cookie = getcookie();
  err = _mkey_encode(req_buf, &reqlen, cookie, MKEY_OP_DECRYPT,
                     1, &kvno, in, tag);
  if (err) return err;

  err = do_request(cookie, reqlen, &replen, &repptr);
  if (err) return err;

  err = _mkey_decode(repptr, replen, 0, 0, 0, 0, &outdata, 0);
  if (err) return err;

  if (outdata.size > out->size)
    return MKEY_ERR_OVERFLOW;
  memcpy(out->data, outdata.data, outdata.size);
  out->size = outdata.size;

  return 0;
}


MKey_Error mkey_add_key(char *tag, MKey_Integer kvno,
                        MKey_Integer enctype, MKey_DataBlock *key)
{
  MKey_Integer intargs[2];
  MKey_Integer cookie;
  MKey_Error err;
  int reqlen, replen;
  char *repptr;

  reqlen = MKEY_MAXSIZE;
  cookie = getcookie();
  intargs[0] = kvno;
  intargs[1] = enctype;
  err = _mkey_encode(req_buf, &reqlen, cookie, MKEY_OP_ADD_KEY,
                     2, intargs, key, tag);
  if (err) return err;

  err = do_request(cookie, reqlen, &replen, &repptr);
  if (err) return err;

  err = _mkey_decode(repptr, replen, 0, 0, 0, 0, 0, 0);
  if (err) return err;

  return 0;
}


MKey_Error mkey_remove_key(char *tag, MKey_Integer kvno)
{
  MKey_Integer cookie;
  MKey_Error err;
  int reqlen, replen;
  char *repptr;

  reqlen = MKEY_MAXSIZE;
  cookie = getcookie();
  err = _mkey_encode(req_buf, &reqlen, cookie, MKEY_OP_REMOVE_KEY,
                     1, &kvno, 0, tag);
  if (err) return err;

  err = do_request(cookie, reqlen, &replen, &repptr);
  if (err) return err;

  err = _mkey_decode(repptr, replen, 0, 0, 0, 0, 0, 0);
  if (err) return err;

  return 0;
}


MKey_Error mkey_verify_key(char *tag, MKey_Integer kvno)
{
  MKey_Integer cookie;
  MKey_Error err;
  int reqlen, replen;
  char *repptr;

  reqlen = MKEY_MAXSIZE;
  cookie = getcookie();
  err = _mkey_encode(req_buf, &reqlen, cookie, MKEY_OP_VERIFY_KEY,
                     1, &kvno, 0, tag);
  if (err) return err;

  err = do_request(cookie, reqlen, &replen, &repptr);
  if (err) return err;

  err = _mkey_decode(repptr, replen, 0, 0, 0, 0, 0, 0);
  if (err) return err;

  return 0;
}


MKey_Error mkey_list_keys(char *tag, MKey_Integer *nkeys, MKey_KeyInfo *keys)
{
  MKey_Integer cookie;
  MKey_Error err;
  int reqlen, replen;
  char *repptr;

  reqlen = MKEY_MAXSIZE;
  cookie = getcookie();
  err = _mkey_encode(req_buf, &reqlen, cookie, MKEY_OP_LIST_KEYS,
                     0, 0, 0, tag);
  if (err) return err;

  err = do_request(cookie, reqlen, &replen, &repptr);
  if (err) return err;

  err = _mkey_decode(repptr, replen, 0, 0, nkeys, keys, 0, 0);
  if (err) return err;

  return 0;
}


MKey_Error mkey_find_largest_kvno(char *tag, MKey_Integer *kvno)
{
  MKey_Error err;
  MKey_KeyInfo keys[512];
  MKey_Integer nkeys, i;

  nkeys = sizeof(keys) / sizeof(MKey_KeyInfo);
  err = mkey_list_keys(tag, &nkeys, keys);
  if (err) return err;
  if (!nkeys) return MKEY_ERR_NO_KEY;

  *kvno = keys[0].kvno;
  for (i = 0; i < nkeys; i++)
    if (*kvno < keys[0].kvno)
      *kvno = keys[0].kvno;
  return 0;
}


MKey_Error mkey_list_tag(MKey_Integer tagid, char *tag, int bufsize)
{
  MKey_Integer cookie;
  MKey_Error err;
  int reqlen, replen;
  char *repptr, *tagout;

  reqlen = MKEY_MAXSIZE;
  cookie = getcookie();
  err = _mkey_encode(req_buf, &reqlen, cookie, MKEY_OP_LIST_TAG,
                     1, &tagid, 0, 0);
  if (err) return err;

  err = do_request(cookie, reqlen, &replen, &repptr);
  if (err) return err;

  err = _mkey_decode(repptr, replen, 0, 0, 0, 0, 0, &tagout);
  if (err) return err;

  if (!bufsize || strlen(tagout) > bufsize - 1)
    return MKEY_ERR_OVERFLOW;
  strcpy(tag, tagout);
  return 0;
}


MKey_Error mkey_shutdown(void)
{
  MKey_Integer cookie;
  MKey_Error err;
  int reqlen, replen;
  char *repptr, *tagout;

  reqlen = MKEY_MAXSIZE;
  cookie = getcookie();
  err = _mkey_encode(req_buf, &reqlen, cookie, MKEY_OP_SHUTDOWN,
                     0, 0, 0, 0);
  if (err) return err;

  err = do_request(cookie, reqlen, &replen, &repptr);
  if (err) return err;

  err = _mkey_decode(repptr, replen, 0, 0, 0, 0, 0, 0);
  if (err) return err;
  return 0;
}
