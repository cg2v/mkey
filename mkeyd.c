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
#include <door.h>

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


static int32_t op_encrypt   (char *reqbuf, int reqlen, char *repbuf, int *replen)
{
}


static int32_t op_decrypt   (char *reqbuf, int reqlen, char *repbuf, int *replen)
{
}


static int32_t op_add_key   (char *reqbuf, int reqlen, char *repbuf, int *replen)
{
}


static int32_t op_remove_key(char *reqbuf, int reqlen, char *repbuf, int *replen)
{
}


static int32_t op_list_keys (char *reqbuf, int reqlen, char *repbuf, int *replen)
{
}


static int32_t op_list_tag  (char *reqbuf, int reqlen, char *repbuf, int *replen)
{
}


static int32_t op_shutdown  (char *reqbuf, int reqlen, char *repbuf, int *replen)
{
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

  argv0 = strrchr(argv[0], '/');
  argv0 = argv0 ? argv0 + 1 : argv[0];

  openlog(argv0, LOG_PID, MKEY_FACILITY);
  syslog(LOG_INFO, "mkeyd %s", "$Revision$");
  mainloop();
}
