/*
 * pkcs15-simple.h: Simplified wrapper for operations on a pkcs#15 smartcard
 *
 * Copyright 2003 Chaskiel Grundman <cg2v@andrew.cmu.edu>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _PKCS15_SIMPLE_H
#define _PKCS15_SIMPLE_H

#include <openssl/rsa.h>

typedef struct p15_simple_s *p15_simple_t;

int p15_simple_init(int reader, p15_simple_t *ctx);
int p15_simple_finish(p15_simple_t ctx);
int p15_simple_getlabel(p15_simple_t ctx, char *label, int outlen);
int p15_simple_getmanuf(p15_simple_t ctx, char *manufacurer_id, int outlen);
int p15_simple_getserial(p15_simple_t ctx, char *serial_number, int outlen);


int p15_simple_setkey(p15_simple_t ctx, char *label);
int p15_simple_setkeyid(p15_simple_t ctx, char *keyid);
int p15_simple_getkeyid(p15_simple_t ctx, char *keyid, int outlen);
int p15_simple_getkeysize(p15_simple_t ctx, int *size);
int p15_simple_getkeydata(p15_simple_t ctx, RSA **ret);
int p15_simple_can_decrypt(p15_simple_t ctx);
int p15_simple_can_sign(p15_simple_t ctx);

/*int p15_simple_encrypt(p15_simple_t ctx, char *inbuf, int inlen,
  char *outbuf, int outlen);*/

int p15_simple_decrypt(p15_simple_t ctx, unsigned char *inbuf, int inlen,
                       unsigned char *outbuf, int *outlen);

int p15_simple_sign_raw(p15_simple_t ctx, unsigned char *inbuf, int inlen,
                       unsigned char *outbuf, int *outlen);
int p15_simple_sign_md5(p15_simple_t ctx, unsigned char *inbuf, int inlen,
                       unsigned char *outbuf, int *outlen);
int p15_simple_sign_sha(p15_simple_t ctx, unsigned char *inbuf, int inlen,
                       unsigned char *outbuf, int *outlen);
int p15_simple_sign_tls(p15_simple_t ctx, unsigned char *inbuf, int inlen,
                       unsigned char *outbuf, int *outlen);

#define OK 0
#define FAIL 1

#endif
