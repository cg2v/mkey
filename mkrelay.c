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
 * mkrelay.c - master key TCP relay agent
 */


#include <sys/types.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <errno.h>

#include <com_err.h>
#include <krb5.h>
#include <sl.h>

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


static char req_buf[MKEY_MAXSIZE + 1];
static char rep_buf[MKEY_MAXSIZE + 1];

static void client_loop(int csock)
{
  MKey_Integer pktsize, cookie, code;
  int n, replen;
  char *repptr;

  for (;;) {
    pktsize = 1;
    n = recv(csock, &pktsize, sizeof(pktsize), RECV_FLAGS);
    if (n < 0 && errno == EINTR) continue;
    if (n == sizeof(pktsize)) {
      pktsize = ntohl(pktsize);
      if (pktsize > MKEY_MAXSIZE) {
        code = htonl(MKEY_ERR_TOO_BIG);
        send(csock, &code, sizeof(code), SEND_FLAGS);
        return;
      }
      for (;;) {
        n = recv(csock, req_buf, pktsize, RECV_FLAGS);
        if (n >= 0 || errno != EINTR) break;
      }
    } else if (n >= 0) n = errno = -1;
    if (n != pktsize) return;
    if (pktsize < 4) {
      /* not even a cookie? */
      cookie = 0;
      code = MKEY_ERR_REQ_FORMAT;
    } else {
      memcpy(&cookie, req_buf, 4);
      cookie = ntohl(cookie);
      code = _mkey_do_request(cookie, req_buf, pktsize,
                              rep_buf, &replen, &repptr);
    }
    if (code) {
      _mkey_encode(rep_buf, &replen, cookie, code, 0, 0, 0, 0);
      repptr = rep_buf;
    }
    pktsize = htonl(replen);
    for (;;) {
      n = send(csock, &pktsize, sizeof(pktsize), SEND_FLAGS);
      if (n >= 0 || errno != EINTR) break;
    }
    if (n == sizeof(pktsize)) {
      for (;;) {
        n = send(csock, repptr, replen, SEND_FLAGS);
        if (n >= 0 || errno != EINTR) break;
      }
    } else if (n >= 0) n = errno = -1;
    if (n != replen) return;
  }
}


static void usage() {
  fprintf(stderr, "Usage: mkrelay [-s sockname]\n");
  exit(1);
}


int main(int argc, char **argv)
{
  struct rlimit rl;
  struct sockaddr_in myaddr, hisaddr;
  int lsock, csock, addrsize, one = 1;

  if (argc > 1) {
    if (!strcmp(argv[1], "-h")) {
      usage();
    } else if (!strcmp(argv[1], "-s") && argc > 2) {
      mkey_set_socket_name(argv[2]);
      argv += 2;
      argc -= 2;
    }
  }
  if (argc > 1) usage();
  if (mlockall(MCL_CURRENT | MCL_FUTURE)) {
    fprintf(stderr, "mlockall: %s\n", strerror(errno));
    if (errno == EPERM)
      fprintf(stderr, "WARNING! Unable to lock pages in memory!\n");
    else
      exit(1);
  }
  memset(&rl, 0, sizeof(rl));
  if (setrlimit(RLIMIT_CORE, &rl)) {
    fprintf(stderr, "setrlimit: %s\n", strerror(errno));
    exit(1);
  }

  lsock = socket(PF_INET, SOCK_STREAM, 0);
  if (lsock < 0) {
    fprintf(stderr, "socket: %s\n", strerror(errno));
    exit(1);
  }
  setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  memset(&myaddr, 0, sizeof(myaddr));
  myaddr.sin_family = AF_INET;
  myaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  myaddr.sin_port = htons(MKEY_RELAY_PORT);
  if (bind(lsock, (struct sockaddr *)&myaddr, sizeof(myaddr))) {
    fprintf(stderr, "bind: %s\n", strerror(errno));
    exit(1);
  }

  if (listen(lsock, 1)) {
    fprintf(stderr, "listen: %s\n", strerror(errno));
    exit(1);
  }

  for (;;) {
    memset(&hisaddr, 0, sizeof(hisaddr));
    addrsize = sizeof(hisaddr);
    csock = accept(lsock, (struct sockaddr *)&hisaddr, &addrsize);
    if (csock < 0) {
      switch (errno) {
        case EINTR:
        case EAGAIN:
        case EPROTO:
        case ENOPROTOOPT:
        case EOPNOTSUPP:
        case EHOSTDOWN:
        case EHOSTUNREACH:
        case ENONET:
        case ENETDOWN:
        case ENETUNREACH:
          continue;
        default:
          fprintf(stderr, "accept: %s\n", strerror(errno));
          exit(1);
      }
    }
    if (addrsize == sizeof(hisaddr) &&
        hisaddr.sin_family == AF_INET &&
        hisaddr.sin_addr.s_addr == htonl(INADDR_LOOPBACK))
      client_loop(csock);
    close(csock);
  }
}
