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


MKey_Error _mkey_encode(char *buf, int *buflen,
                        MKey_Integer cookie, MKey_Integer code,
                        int nints, MKey_Integer *ints,
                        MKey_DataBlock *data, char *string)
{
  int pktlen, offset, i;

  pktlen = 4 * (2 + nints);
  if (data)   pktlen += 4 + data->size;
  if (string) pktlen += strlen(string) + 1;
  if (pktlen > *buflen) return MKEY_ERR_TOO_BIG;

  offset = 0;
  memcpy(buf + offset, &cookie, 4);               offset += 4;
  memcpy(buf + offset, &code, 4);                 offset += 4;
  for (i = 0; i < nints; i++) {
    memcpy(buf + offset, ints+i, 4);              offset += 4;
  }
  if (data) {
    memcpy(buf + offset, &data->size, 4);         offset += 4;
    memcpy(buf + offset, data->data, data->size); offset += data->size;
  }
  if (string) {
    strcpy(buf + offset, string);
  }
  *buflen = pktlen;
  return 0;
}


MKey_Error _mkey_decode_header(char *buf, int buflen,
                               MKey_Integer *cookie, MKey_Integer *code)
{
  if (buflen < 8) return MKEY_ERR_MSG_FORMAT;
  memcpy(cookie, buf, 4);
  memcpy(code, buf + 4, 4);
  return 0;
}


MKey_Error _mkey_decode(char *buf, int buflen,
                        int nints, MKey_Integer *ints,
                        MKey_Integer *nkeys, MKey_KeyInfo *keys,
                        MKey_DataBlock *data, char **string)
{
  int pktlen, offset, i;
  MKey_Integer datasize, keycount;

  offset = 8; /* skip cookie and code */
  if (offset > buflen) return MKEY_ERR_MSG_FORMAT;

  for (i = 0; i < nints; i++) {
    if (buflen - offset < 4) return MKEY_ERR_MSG_FORMAT;
    memcpy(ints+i, buf + offset, 4);              offset += 4;
  }
  if (data) {
    if (buflen - offset < 4) return MKEY_ERR_MSG_FORMAT;
    memcpy(&datasize, buf + offset, 4);           offset += 4;

    if (buflen - offset < datasize) return MKEY_ERR_MSG_FORMAT;
    if (datasize > data->size) return MKEY_ERR_OVERFLOW;
    data->size = datasize;
    memcpy(data->data, buf + offset, datasize);
    offset += datasize;
  }
  if (nkeys) {
    if (buflen - offset < 4) return MKEY_ERR_MSG_FORMAT;
    memcpy(&keycount, buf + offset, 4);           offset += 4;

    if (keycount > *nkeys) return MKEY_ERR_OVERFLOW;
    *nkeys = keycount;
    for (i = 0; i < keycount; i++) {
      if (buflen - offset < 8) return MKEY_ERR_MSG_FORMAT;
      memcpy(&keys[i].kvno,    buf + offset, 4);  offset += 4;
      memcpy(&keys[i].enctype, buf + offset, 4);  offset += 4;
    }
  }
  if (string) {
    /* the rest of the packet is the string */
    /* it must be at least 1 byte long */
    if (buflen - offset < 1) return MKEY_ERR_MSG_FORMAT;
    buf[buflen - 1] = 0;
    *string = buf + offset;
  } else {
    if (buflen - offset) return MKEY_ERR_MSG_FORMAT;
  }
  return 0;
}
