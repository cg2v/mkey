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
 * libmkey.c - mkey library implementation
 */

#define _XOPEN_SOURCE
#define _XOPEN_SOURCE_EXTENDED 1 /* for strdup */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/un.h>
#ifdef USE_DOORS
#include <door.h>
#endif
#include <errno.h>

#include "mkey_err.h"
#include "libmkey.h"
#include "mkey.h"


#ifdef MSG_NOSIGNAL
#define SEND_FLAGS (MSG_DONTWAIT|MSG_NOSIGNAL)
#define RECV_FLAGS (MSG_WAITALL|MSG_NOSIGNAL)
#else
#define SEND_FLAGS 0
#define RECV_FLAGS 0
#endif

static char *mkey_sock_name = 0;
static char req_buf[MKEY_MAXSIZE + 1];
static char rep_buf[MKEY_MAXSIZE + 1];
static MKey_Integer global_cookie = 0;
static int mkeyd_sock = -1;
static int use_mkrelay = 0;


static MKey_Integer getcookie(void)
{
  if (!global_cookie) {
    srand(time(0) ^ getpid());
    global_cookie = rand();
  }
  global_cookie++;
  return global_cookie;
}

#define STREAM_REQ_BIG  -4  // received length too big; try again
#define STREAM_REQ_INTR -3  // got EINTR; try again
#define STREAM_REQ_ERR  -2  // generic error; see errno
#define STREAM_REQ_EOF  -1  // stream closed; try again
#define STREAM_REQ_OK    0  // OK to process request

static int _mkey_do_stream_req(char *reqBUF, int reqlen,
                               char *repBUF, int *replen, char **repptr)
{
  MKey_Integer pktsize;
  int n;

  /* Send off our request */
  pktsize = htonl(reqlen);
  n = send(mkeyd_sock, &pktsize, sizeof(pktsize), SEND_FLAGS);
  if (n < 0 && errno == EINTR) return STREAM_REQ_INTR;
  if (n == sizeof(pktsize)) {
    while (reqlen != 0) {
      n = send(mkeyd_sock, reqBUF, reqlen, SEND_FLAGS);
      if (n >= 0 || errno != EINTR) break;
    }
  }
  else if (n >= 0) n = errno = -1;
  if (n != reqlen) {
    switch (errno) {
      default:
        return STREAM_REQ_ERR;
      case -1:
      case EPIPE:
      case EBADF:
      case EAGAIN:
        close(mkeyd_sock);
        mkeyd_sock = -1;
        return STREAM_REQ_EOF;
    }
  }

  pktsize = 1;
  for (;;) {
    n = recv(mkeyd_sock, &pktsize, sizeof(pktsize), RECV_FLAGS);
    if (n >= 0 || errno != EINTR) break;
  }
  if (n == sizeof(pktsize)) {
    pktsize = ntohl(pktsize);
    if (pktsize > MKEY_MAXSIZE) {
      /* overflow; try again */
      close(mkeyd_sock);
      mkeyd_sock = -1;
      return STREAM_REQ_BIG;
    }
    while (pktsize != 0) {
      n = recv(mkeyd_sock, repBUF, pktsize, RECV_FLAGS);
      if (n >= 0 || errno != EINTR) break;
    }
  } else if (n >= 0) n = errno = -1;

  if (n != pktsize) {
    switch (errno) {
      default:
        return STREAM_REQ_ERR;
      case -1:
      case EPIPE:
      case EBADF:
      case EAGAIN:
        close(mkeyd_sock);
        mkeyd_sock = -1;
        return STREAM_REQ_EOF;
    }
  }
  *repptr = repBUF;
  *replen = pktsize;
  return STREAM_REQ_OK;
}

MKey_Error _mkey_do_request(MKey_Integer cookie, char *reqBUF, int reqlen,
                            char *repBUF, int *replen, char **repptr)
{
  MKey_Integer rcookie;
  MKey_Error err, errcode, lasterr;
#ifdef USE_DOORS
  door_arg_t arg;
#endif
  int try, xerrno, port;
  char *sock_name;
  struct sockaddr_in relay;

  sock_name = mkey_sock_name ? mkey_sock_name : MKEY_SOCKET;
  lasterr = MKEY_ERR_TIMEOUT;
  for (try = 0; try < 3;) {
    if (use_mkrelay) {
      if (mkeyd_sock < 0) {
        mkeyd_sock = socket(PF_INET, SOCK_STREAM, 0);
        if (mkeyd_sock < 0) return errno;

        if (mkey_sock_name && mkey_sock_name[0] == ':') {
          port = atol(mkey_sock_name + 1);
          if (port < 0 || port > 0xffff) port = MKEY_RELAY_PORT;
        } else port = MKEY_RELAY_PORT;
        memset(&relay, 0, sizeof(relay));
        relay.sin_family = AF_INET;
        relay.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        relay.sin_port = htons(port);
        if (connect(mkeyd_sock, (struct sockaddr *)&relay, sizeof(relay))) {
          xerrno = errno;
          close(mkeyd_sock);
          mkeyd_sock = -1;
          return xerrno;
        }
      }

      switch (_mkey_do_stream_req(reqBUF, reqlen, repBUF, replen, repptr)) {
        // These three are a sequence...
        case STREAM_REQ_BIG:  lasterr = MKEY_ERR_TOO_BIG; /* Falls through. */
        case STREAM_REQ_EOF:  try++; /* Falls through. */
        case STREAM_REQ_INTR: continue;

        case STREAM_REQ_OK:   break;
        case STREAM_REQ_ERR:  return errno;
        default:              return EIO;       // should never happen
      }

    } else {
#ifdef USE_DOORS
      if (mkeyd_sock < 0) {
        mkeyd_sock = open(sock_name, O_RDONLY);
        if (mkeyd_sock < 0) return errno;
      }

      arg.data_ptr = reqBUF;
      arg.data_size = reqlen;
      arg.desc_ptr = 0;
      arg.desc_num = 0;
      arg.rbuf = repBUF;
      arg.rsize = MKEY_MAXSIZE;

      if (door_call(mkeyd_sock, &arg)) {
        switch (errno) {
          default:        return errno;
          case EOVERFLOW: return MKEY_ERR_TOO_BIG;
          case EINTR:     continue;
          case EBADF:
          case EAGAIN:
            try++;
            close(mkeyd_sock);
            mkeyd_sock = -1;
            continue;
        }
      }
      if (arg.rbuf != repBUF) {
        munmap(arg.rbuf, arg.rsize);
        return MKEY_ERR_TOO_BIG;
      }

      *repptr = arg.data_ptr;
      *replen = arg.data_size;
#else /* !USE_DOORS */

      if (mkeyd_sock < 0) {
        struct sockaddr_un server;
        unsigned int socklen = strlen(sock_name) + 1;

        if (socklen > sizeof(server.sun_path))
          return ENAMETOOLONG;

        memset(&server, 0, sizeof(server));
        server.sun_family = AF_UNIX;
        strcpy(server.sun_path, sock_name);
        socklen += sizeof(server) - sizeof(server.sun_path);

        mkeyd_sock = socket(PF_UNIX, SOCK_STREAM, 0);
        if (mkeyd_sock < 0) return errno;
        if (connect(mkeyd_sock, (struct sockaddr *)&server, socklen)) {
          xerrno = errno;
          close(mkeyd_sock);
          mkeyd_sock = -1;
          return xerrno;
        }
      }

      switch (_mkey_do_stream_req(reqBUF, reqlen, repBUF, replen, repptr)) {
        // These three are a sequence...
        case STREAM_REQ_BIG:  lasterr = MKEY_ERR_TOO_BIG; /* Falls through. */
        case STREAM_REQ_EOF:  try++; /* Falls through. */
        case STREAM_REQ_INTR: continue;

        case STREAM_REQ_OK:   break;
        case STREAM_REQ_ERR:  return errno;
        default:              return EIO;       // should never happen
      }
#endif /* USE_DOORS */
    }

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

static MKey_Error do_request(MKey_Integer cookie, int reqlen,
                             int *replen, char **repptr)
{
  return _mkey_do_request(cookie, req_buf, reqlen, rep_buf, replen, repptr);
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

  if (!bufsize || strlen(tagout) > (unsigned int)bufsize - 1)
    return MKEY_ERR_OVERFLOW;
  strcpy(tag, tagout);
  return 0;
}


MKey_Error mkey_generate_key(MKey_Integer enctype, MKey_DataBlock *key)
{
  MKey_DataBlock outdata;
  MKey_Integer cookie;
  MKey_Error err;
  int reqlen, replen;
  char *repptr;

  reqlen = MKEY_MAXSIZE;
  cookie = getcookie();
  err = _mkey_encode(req_buf, &reqlen, cookie, MKEY_OP_GENERATE_KEY,
                     1, &enctype, 0, 0);
  if (err) return err;

  err = do_request(cookie, reqlen, &replen, &repptr);
  if (err) return err;

  err = _mkey_decode(repptr, replen, 0, 0, 0, 0, &outdata, 0);
  if (err) return err;

  if (outdata.size > key->size)
    return MKEY_ERR_OVERFLOW;
  memcpy(key->data, outdata.data, outdata.size);
  key->size = outdata.size;

  return 0;
}


MKey_Error mkey_string_to_enctype(char *name, MKey_Integer *enctype)
{
  MKey_Integer cookie;
  MKey_Error err;
  int reqlen, replen;
  char *repptr;

  reqlen = MKEY_MAXSIZE;
  cookie = getcookie();
  err = _mkey_encode(req_buf, &reqlen, cookie, MKEY_OP_STRING_TO_ETYPE,
                     0, 0, 0, name);
  if (err) return err;

  err = do_request(cookie, reqlen, &replen, &repptr);
  if (err) return err;

  err = _mkey_decode(repptr, replen, 1, enctype, 0, 0, 0, 0);
  if (err) return err;

  return 0;
}


MKey_Error mkey_enctype_to_string(MKey_Integer enctype, char *name, int bufsize)
{
  MKey_Integer cookie;
  MKey_Error err;
  int reqlen, replen;
  char *repptr, *nameout;

  reqlen = MKEY_MAXSIZE;
  cookie = getcookie();
  err = _mkey_encode(req_buf, &reqlen, cookie, MKEY_OP_ETYPE_TO_STRING,
                     1, &enctype, 0, 0);
  if (err) return err;

  err = do_request(cookie, reqlen, &replen, &repptr);
  if (err) return err;

  err = _mkey_decode(repptr, replen, 0, 0, 0, 0, 0, &nameout);
  if (err) return err;

  if (!bufsize || strlen(nameout) > (unsigned int)bufsize - 1)
    return MKEY_ERR_OVERFLOW;
  strcpy(name, nameout);
  return 0;
}


MKey_Error mkey_get_metakey_info(char *tag, MKey_Integer *state,
                                 MKey_Integer *kvno, MKey_Integer *enctype)
{
  MKey_Integer cookie, iresult[3];
  MKey_Error err;
  int reqlen, replen;
  char *repptr;

  reqlen = MKEY_MAXSIZE;
  cookie = getcookie();
  err = _mkey_encode(req_buf, &reqlen, cookie, MKEY_OP_GET_METAKEY_INFO,
                     0, 0, 0, tag);
  if (err) return err;

  err = do_request(cookie, reqlen, &replen, &repptr);
  if (err) return err;

  err = _mkey_decode(repptr, replen, 3, iresult, 0, 0, 0, 0);
  if (err) return err;

  *state = iresult[0];
  *kvno = iresult[1];
  *enctype = iresult[2];
  return 0;
}


MKey_Error mkey_unseal_keys(char *tag, MKey_Integer enctype, MKey_DataBlock *key)
{
  MKey_Integer cookie;
  MKey_Error err;
  int reqlen, replen;
  char *repptr;

  reqlen = MKEY_MAXSIZE;
  cookie = getcookie();
  err = _mkey_encode(req_buf, &reqlen, cookie, MKEY_OP_UNSEAL_KEYS,
                     1, &enctype, key, tag);
  if (err) return err;

  err = do_request(cookie, reqlen, &replen, &repptr);
  if (err) return err;

  err = _mkey_decode(repptr, replen, 0, 0, 0, 0, 0, 0);
  if (err) return err;

  return 0;
}


MKey_Error mkey_set_metakey(char *tag, MKey_Integer kvno,
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
  err = _mkey_encode(req_buf, &reqlen, cookie, MKEY_OP_SET_METAKEY,
                     2, intargs, key, tag);
  if (err) return err;

  err = do_request(cookie, reqlen, &replen, &repptr);
  if (err) return err;

  err = _mkey_decode(repptr, replen, 0, 0, 0, 0, 0, 0);
  if (err) return err;

  return 0;
}


MKey_Error mkey_store_keys(char *tag)
{
  MKey_Integer cookie;
  MKey_Error err;
  int reqlen, replen;
  char *repptr;

  reqlen = MKEY_MAXSIZE;
  cookie = getcookie();
  err = _mkey_encode(req_buf, &reqlen, cookie, MKEY_OP_STORE_KEYS,
                     0, 0, 0, tag);
  if (err) return err;

  err = do_request(cookie, reqlen, &replen, &repptr);
  if (err) return err;

  err = _mkey_decode(repptr, replen, 0, 0, 0, 0, 0, 0);
  if (err) return err;

  return 0;
}


MKey_Error mkey_load_keys(char *tag)
{
  MKey_Integer cookie;
  MKey_Error err;
  int reqlen, replen;
  char *repptr;

  reqlen = MKEY_MAXSIZE;
  cookie = getcookie();
  err = _mkey_encode(req_buf, &reqlen, cookie, MKEY_OP_LOAD_KEYS,
                     0, 0, 0, tag);
  if (err) return err;

  err = do_request(cookie, reqlen, &replen, &repptr);
  if (err) return err;

  err = _mkey_decode(repptr, replen, 0, 0, 0, 0, 0, 0);
  if (err) return err;

  return 0;
}


MKey_Error mkey_shutdown(void)
{
  MKey_Integer cookie;
  MKey_Error err;
  int reqlen, replen;
  char *repptr;

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


void mkey_set_socket_name(char *sock_name)
{
  if (sock_name) {
    sock_name = strdup(sock_name);
    if (!sock_name) return;
  }

  if (mkey_sock_name) free(mkey_sock_name);
  mkey_sock_name = sock_name;
  use_mkrelay = (sock_name[0] == ':');
}
