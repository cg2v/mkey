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
 * mkey protocol encoding
 */

#include <string.h>

#include "libmkey.h"
#include "mkey_err.h"
#include "mkey.h"


MKey_Error _mkey_encode(void *buf, int *buflen,
                        MKey_Integer cookie, MKey_Integer code,
                        int nints, MKey_Integer *ints,
                        MKey_DataBlock *data, char *string)
{
  unsigned char *bytes = buf;
  int pktlen, offset, i;
  MKey_Integer netint;

  pktlen = 4 * (2 + nints);
  if (data)   pktlen += 4 + data->size;
  if (string) pktlen += strlen(string) + 1;
  if (pktlen > *buflen) return MKEY_ERR_TOO_BIG;

  offset = 0;

  netint = htonl(cookie);
  memcpy(bytes + offset, &netint, 4);
  offset += 4;

  netint = htonl(code);
  memcpy(bytes + offset, &netint, 4);
  offset += 4;

  for (i = 0; i < nints; i++) {
    netint = htonl(ints[i]);
    memcpy(bytes + offset, &netint, 4);
    offset += 4;
  }

  if (data) {
    netint = htonl(data->size);
    memcpy(bytes + offset, &netint, 4);
    offset += 4;
    memcpy(bytes + offset, data->data, data->size);
    offset += data->size;
  }
  if (string) {
    strcpy((char *)(bytes + offset), string);
  }
  *buflen = pktlen;
  return 0;
}


MKey_Error _mkey_decode_header(void *buf, int buflen,
                               MKey_Integer *cookie, MKey_Integer *code)
{
  unsigned char *bytes = buf;
  MKey_Integer netint;

  if (buflen < 8) return MKEY_ERR_MSG_FORMAT;
  memcpy(&netint, bytes, 4);
  *cookie = ntohl(netint);
  memcpy(&netint, bytes + 4, 4);
  *code = ntohl(netint);
  return 0;
}


MKey_Error _mkey_decode(void *buf, int buflen,
                        int nints, MKey_Integer *ints,
                        MKey_Integer *nkeys, MKey_KeyInfo *keys,
                        MKey_DataBlock *data, char **string)
{
  unsigned char *bytes = buf;
  int pktlen, offset, i;
  MKey_Integer datasize, keycount, netint;

  offset = 8; /* skip cookie and code */
  if (offset > buflen) return MKEY_ERR_MSG_FORMAT;

  for (i = 0; i < nints; i++) {
    if (buflen - offset < 4) return MKEY_ERR_MSG_FORMAT;
    memcpy(&netint, bytes + offset, 4);
    offset += 4;
    ints[i] = ntohl(netint);
  }
  if (data) {
    if (buflen - offset < 4) return MKEY_ERR_MSG_FORMAT;
    memcpy(&netint, bytes + offset, 4);
    offset += 4;
    datasize = ntohl(netint);

    if (buflen - offset < datasize) return MKEY_ERR_MSG_FORMAT;
    data->size = datasize;
    data->data = bytes + offset;
    offset += datasize;
  }
  if (nkeys) {
    if (buflen - offset < 4) return MKEY_ERR_MSG_FORMAT;
    memcpy(&netint, bytes + offset, 4);
    offset += 4;
    keycount = ntohl(netint);

    if (keycount > *nkeys) return MKEY_ERR_OVERFLOW;
    *nkeys = keycount;
    for (i = 0; i < keycount; i++) {
      if (buflen - offset < 8) return MKEY_ERR_MSG_FORMAT;
      memcpy(&netint, bytes + offset, 4);
      offset += 4;
      keys[i].kvno = ntohl(netint);
      memcpy(&netint, bytes + offset, 4);
      offset += 4;
      keys[i].enctype = ntohl(netint);
    }
  }
  if (string) {
    /* the rest of the packet is the string */
    /* it must be at least 1 byte long */
    if (buflen - offset < 1) return MKEY_ERR_MSG_FORMAT;
    bytes[buflen - 1] = 0;
    *string = (char *)(bytes + offset);
  } else {
    if (buflen - offset) return MKEY_ERR_MSG_FORMAT;
  }
  return 0;
}
