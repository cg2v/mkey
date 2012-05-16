/*
 * pkcs15-simple.c: Simplified wrapper for operations on a pkcs#15 smartcard
 *
 * Copyright 2003  Chaskiel Grundman <cg2v@andrew.cmu.edu>
 * Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>

#include <opensc/pkcs15.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#include <libmkey.h>
#include "pkcs15-simple.h"

struct p15_simple_s 
{
     sc_context_t *ctx;
     sc_card_t *card;
     sc_pkcs15_card_t *p15card;
     int can_decrypt;
     int can_sign;
     int keyisset;
     int locked;
     int haspin;
     sc_pkcs15_id_t id;
     char keyid[2*SC_PKCS15_MAX_ID_SIZE+1];
     sc_pkcs15_object_t *obj_pubkey, *obj_prkey_dec, 
          *obj_prkey_sign, *obj_cert, *obj_pin;
     sc_pkcs15_pubkey_t *pubkey;
     sc_pkcs15_cert_t *cert;
};


int p15_simple_init(int reader_id, p15_simple_t *ctx) {
     struct p15_simple_s *ret;
     sc_reader_t *reader;
     int status;
     
     ret=OPENSSL_malloc(sizeof(struct p15_simple_s));
     if (!ret)
          return FAIL;
     memset(ret,0,sizeof(struct p15_simple_s));
     
     status=sc_establish_context(&ret->ctx, "simpleapp");
     if (status) {
          fprintf(stderr, "Failed to establish context: %s\n", 
                  sc_strerror(status));
          goto fail_init;
     }
     //ret->ctx->debug=10;
     
     if (ret->ctx->reader_count == 0) {
          fprintf(stderr,
                  "No smart card readers configured.\n");
	  goto fail_init;
     }
     if (reader_id >= ret->ctx->reader_count) {
          fprintf(stderr,
                  "Illegal reader number. "
                  "Only %d reader(s) configured.\n",
                  ret->ctx->reader_count);
	  goto fail_init;
     }

     reader = ret->ctx->reader[reader_id];
     if (sc_detect_card_presence(reader, 0) <= 0) {
          fprintf(stderr, "Card not present.\n");
	  goto fail_init;
     }
     
     if ((status = sc_connect_card(reader, 0, &ret->card)) < 0) {
          fprintf(stderr,
                  "Failed to connect to card: %s\n",
                  sc_strerror(status));
	  goto fail_init;
     }

     status=sc_lock(ret->card);
     if (status) {
          fprintf(stderr, "Failed to lock card: %s\n", sc_strerror(status));
          goto fail_init;
     }
     ret->locked=1;
     status=sc_pkcs15_bind(ret->card, &ret->p15card);
     if (status) {
          fprintf(stderr, "Failed to find PKCS#15 compatible card: %s\n", sc_strerror
                  (status));
          goto fail_init;
     }

     *ctx=ret;
     return OK;
     
 fail_init:
     if (ret->p15card)
          sc_pkcs15_unbind(ret->p15card);
     if (ret->locked)
          sc_unlock(ret->card);
     if (ret->card)
          sc_disconnect_card(ret->card, SC_DISCONNECT);
     if (ret->ctx)
          sc_release_context(ret->ctx);
     OPENSSL_free(ret);
     return FAIL;
}

int p15_simple_getlabel(p15_simple_t ctx, char *out, int outlen) {
     if (!ctx->p15card)
          return FAIL;
     if (outlen < 0 || (unsigned)outlen < strlen(ctx->p15card->label))
          return FAIL;
     strcpy(out, ctx->p15card->label);
     return OK;
}


int p15_simple_getmanuf(p15_simple_t ctx, char *out, int outlen) {
     if (!ctx->p15card)
          return FAIL;
     if (outlen < 0 || (unsigned)outlen < strlen(ctx->p15card->manufacturer_id))
          return FAIL;
     strcpy(out, ctx->p15card->manufacturer_id);
     return OK;
}


int p15_simple_getserial(p15_simple_t ctx, char *out, int outlen) {
     if (!ctx->p15card)
          return FAIL;
     if (outlen < 0 || (unsigned)outlen < strlen(ctx->p15card->serial_number))
          return FAIL;
     strcpy(out, ctx->p15card->serial_number);
     return OK;
}

     

int p15_simple_finish(p15_simple_t ctx) {
     if (ctx->cert)
	  sc_pkcs15_free_certificate(ctx->cert);
     else if (ctx->pubkey)
	  sc_pkcs15_free_pubkey(ctx->pubkey);
     if (ctx->p15card)
          sc_pkcs15_unbind(ctx->p15card);
     if (ctx->locked)
          sc_unlock(ctx->card);
     if (ctx->card)
          sc_disconnect_card(ctx->card, SC_DISCONNECT);
     if (ctx->ctx)
          sc_release_context(ctx->ctx);
     OPENSSL_free(ctx);
     return OK;
}

static int setkey_common(p15_simple_t ctx) {
     int pubkeystatus, certstatus, prkeystatus, 
          prkeystatus1, prkeystatus2, pinstatus;
     unsigned int i;
     char *keyid;
     sc_pkcs15_object_t *any_prkey;
     
     ctx->can_decrypt=0;
     ctx->can_sign=0;
     ctx->keyisset=0;
     for (i=0;i<ctx->id.len;i++)
          sprintf(&ctx->keyid[2*i], "%02X", ctx->id.value[i]);
     keyid=ctx->keyid;

     pubkeystatus = sc_pkcs15_find_pubkey_by_id(ctx->p15card, &ctx->id, 
                                              &ctx->obj_pubkey);
     prkeystatus1 = sc_pkcs15_find_prkey_by_id_usage
          (ctx->p15card, &ctx->id, SC_PKCS15_PRKEY_USAGE_DECRYPT,
           &ctx->obj_prkey_dec);

     prkeystatus2 = sc_pkcs15_find_prkey_by_id_usage
          (ctx->p15card, &ctx->id, SC_PKCS15_PRKEY_USAGE_SIGN,
           &ctx->obj_prkey_sign);

     certstatus = sc_pkcs15_find_cert_by_id(ctx->p15card, &ctx->id, 
                                              &ctx->obj_cert);
     
     if (certstatus >= 0) {
	  certstatus = sc_pkcs15_read_certificate
               (ctx->p15card, (sc_pkcs15_cert_info_t *) ctx->obj_cert->data, 
                &ctx->cert);
          if (certstatus >= 0) {
               ctx->pubkey=&ctx->cert->key;
               pubkeystatus=0;
          }
     }
     
     if (certstatus < 0 && pubkeystatus >= 0) {
	  pubkeystatus = sc_pkcs15_read_pubkey(ctx->p15card, ctx->obj_pubkey, 
                                               &ctx->pubkey);
     } 
     if (prkeystatus1 == 0)
          any_prkey=ctx->obj_prkey_dec;
     else if (prkeystatus2 == 0)
          any_prkey=ctx->obj_prkey_sign;

     if (prkeystatus1 == SC_ERROR_OBJECT_NOT_FOUND 
          && prkeystatus2 == SC_ERROR_OBJECT_NOT_FOUND)
          prkeystatus=SC_ERROR_OBJECT_NOT_FOUND;
     else if (prkeystatus1 == SC_ERROR_OBJECT_NOT_FOUND 
          && prkeystatus2 == 0) 
          prkeystatus=0;
     else if (prkeystatus1 == 0 
          && prkeystatus2 == SC_ERROR_OBJECT_NOT_FOUND)
          prkeystatus=0;
     else if (prkeystatus1 < 0)
          prkeystatus=prkeystatus1;
     else if (prkeystatus2 < 0)
          prkeystatus=prkeystatus2;
     

     if (pubkeystatus == SC_ERROR_OBJECT_NOT_FOUND || 
         prkeystatus == SC_ERROR_OBJECT_NOT_FOUND) {
          fprintf(stderr, "Key id %s not present on this card\n", keyid);
          goto fail_setkey;
          
     }
     if (pubkeystatus < 0) {
          fprintf(stderr, "Failed to find public key %s: %s\n", keyid, 
                  sc_strerror(pubkeystatus));
          goto fail_setkey;
     }    

     if (prkeystatus < 0) {
          fprintf(stderr, "Failed to find private key %s: %s\n", keyid, 
                  sc_strerror(prkeystatus));
          goto fail_setkey;
     }    
     if (ctx->pubkey->algorithm != SC_ALGORITHM_RSA) {
          fprintf(stderr, "Key %s is not an RSA key\n", keyid);
          goto fail_setkey;
     }
     if (!((struct sc_pkcs15_prkey_info *) any_prkey->data)->native) {
	  fprintf(stderr, "non-native Private key %s is not supported\n",
		  keyid);
          goto fail_setkey;

     }
     if (any_prkey->auth_id.len) {
	  pinstatus = sc_pkcs15_find_pin_by_auth_id
               (ctx->p15card, &any_prkey->auth_id, &ctx->obj_pin);
	  if (pinstatus == SC_ERROR_OBJECT_NOT_FOUND) {
	       fprintf(stderr, 
		       "Pin for Private Key id %s not present on this card\n",
		       keyid);
	       goto fail_setkey;
	       
	  } else if (pinstatus < 0) {
	       fprintf(stderr, 
		       "Failed to find private key %s's pin: %s\n",
		       keyid, sc_strerror(pinstatus));
	       goto fail_setkey;
	  }
          ctx->haspin=1;
     }
     ctx->keyisset=1;
     if (prkeystatus1 == 0)
          ctx->can_decrypt=1;
     if (prkeystatus2 == 0)
          ctx->can_sign=1;
     
     return OK;
 fail_setkey:
     if (ctx->cert)
	  sc_pkcs15_free_certificate(ctx->cert);
     else
	  sc_pkcs15_free_pubkey(ctx->pubkey);
     ctx->pubkey=NULL;
     ctx->cert=NULL;
     ctx->obj_prkey_dec=NULL;
     ctx->obj_prkey_sign=NULL;
     ctx->obj_cert=NULL;
     ctx->obj_pin=NULL;
     memset(&ctx->id, 0, sizeof(sc_pkcs15_id_t));
     return FAIL;
}

int p15_simple_setkeyid(p15_simple_t ctx, char *keyid) {
     ctx->id.len = SC_PKCS15_MAX_ID_SIZE;
     sc_pkcs15_hex_string_to_id(keyid, &ctx->id);
     return setkey_common(ctx);
}

static int compare_obj_keylabel(struct sc_pkcs15_object *obj, void *arg) {

     char *label=(char *)arg;
     struct sc_pkcs15_prkey_info *info;
     
     info=(struct sc_pkcs15_prkey_info *)obj->data;
     
     return !strcmp(obj->label,label);
}


int p15_simple_setkey(p15_simple_t ctx, char *label) {
     int count;
     sc_pkcs15_object_t *prkey;
     sc_pkcs15_prkey_info_t *info;
     

     count = sc_pkcs15_get_objects_cond
          (ctx->p15card, SC_PKCS15_TYPE_PRKEY_RSA, compare_obj_keylabel,
           label, &prkey, 1);
     
     if (count < 1) {
          fprintf(stderr, "Key %s not present on this card\n", label);
          return FAIL;
     }
     
     info=(struct sc_pkcs15_prkey_info *)prkey->data;

     if (info->id.len > SC_PKCS15_MAX_ID_SIZE) {
          fprintf(stderr, "Key %s's id is corrupt\n", label);
          return FAIL;
     }
     
     ctx->id.len=info->id.len;
     
     memcpy(ctx->id.value, info->id.value, ctx->id.len);
     return setkey_common(ctx);
}

int p15_simple_can_decrypt(p15_simple_t ctx) {
     return (ctx->keyisset && ctx->can_decrypt);
}

int p15_simple_can_sign(p15_simple_t ctx){
     return (ctx->keyisset && ctx->can_sign);
}


int p15_simple_getkeyid(p15_simple_t ctx, char *keyid, int outlen) {
     if (!ctx->keyisset)
          return FAIL;
     if (outlen < 0 || (unsigned)outlen <= strlen(ctx->keyid))
          return FAIL;
     strcpy(keyid, ctx->keyid);
     return OK;
}


int p15_simple_getkeysize(p15_simple_t ctx, int *size) {
     
     if (!ctx->keyisset)
          return FAIL;
     *size=ctx->pubkey->u.rsa.modulus.len;
     return OK;
}

int p15_simple_getkeydata(p15_simple_t ctx, RSA **key) {
     RSA *ret;
     if (!ctx->keyisset)
          return FAIL;

     ret=RSA_new();
     if (!ret) {
	  fprintf(stderr, "RSA_new failed while exporting public key\n");
          return FAIL;
     }  
     ret->n=BN_new();
     ret->e=BN_new();

     if (!ret->n || !ret->e) {
	  fprintf(stderr, "BN_new failed while exporting public key\n");
          goto fail_getkeydata;
     }  
     
     if (!BN_bin2bn(ctx->pubkey->u.rsa.modulus.data, ctx->pubkey->u.rsa.modulus.len,
                    ret->n)) {
          fprintf(stderr, "RSA key parse failed while exporting public key\n");
          goto fail_getkeydata;
     }

     if (!BN_bin2bn(ctx->pubkey->u.rsa.exponent.data, ctx->pubkey->u.rsa.exponent.len,
                    ret->e)) {
          fprintf(stderr, "RSA key parse failed while exporting public key\n");
          goto fail_getkeydata;
     }
     *key=ret;
     return OK;
 fail_getkeydata:
     RSA_free(ret);
     return FAIL;
}

static int prkey_setup(p15_simple_t ctx) {
     int status;
     if (!ctx->keyisset) 
          return FAIL;
     
     if (ctx->haspin) {
          char prompt[80];
          char pincode[80];
               
	  sprintf(prompt, "Enter PIN [%s]: ", ctx->obj_pin->label);
	  while (1) {
	       struct sc_pkcs15_pin_info *pinfo = 
		    (struct sc_pkcs15_pin_info *) ctx->obj_pin->data;

	       if (mkey_read_pw_string(pincode, sizeof(pincode), prompt, 0))
		    goto fail_decrypt;
	       if (strlen(pincode) == 0) {
		    fprintf(stderr, "Pin entry aborted\n");
		    goto fail_decrypt;
	       }
	       if (strlen(pincode) < pinfo->min_length ||
		   strlen(pincode) > pinfo->max_length)
		    continue;
	       break;
	  }
	  status = sc_pkcs15_verify_pin(ctx->p15card, 
					(struct sc_pkcs15_pin_info *)ctx->obj_pin->data,
                                        (const u8 *) pincode, strlen(pincode));
	  if (status) {
	       fprintf(stderr, "PIN code verification failed: %s\n", 
		       sc_strerror(status));
	       goto fail_decrypt;
	  }
     }
     return OK;
 fail_decrypt:
     return FAIL;
}

int p15_simple_decrypt(p15_simple_t ctx, unsigned char *inbuf, int inlen,
                       unsigned char *outbuf, int *outlen) {
     int status;
     if (!ctx->can_decrypt)
          return FAIL;

     if (prkey_setup(ctx)) 
          return FAIL;
     if (inlen < 0 || (unsigned)inlen != ((sc_pkcs15_prkey_info_t *)ctx->obj_prkey_dec->data)->modulus_length/8) {
          fprintf(stderr, "Input buffer is wrong length\n");
          goto fail_decrypt;
     }
     if (*outlen < 0 || (unsigned)*outlen < ((sc_pkcs15_prkey_info_t *)ctx->obj_prkey_dec->data)->modulus_length/8) {
          fprintf(stderr, "output buffer is too small\n");
          goto fail_decrypt;
     }
     
     status=sc_pkcs15_decipher(ctx->p15card, ctx->obj_prkey_dec, 
                               SC_ALGORITHM_RSA_PAD_PKCS1,
			       inbuf, inlen, outbuf, *outlen);
     if (status < 0) {
          fprintf(stderr, "Decrypt failed: %s\n", sc_strerror(status));
          goto fail_decrypt;
     }
     *outlen=status;
     return OK;
 fail_decrypt:
     return FAIL;
}



static int do_sign(p15_simple_t ctx, unsigned char *inbuf, int inlen,
                       unsigned char *outbuf, int *outlen, int flags) {
     int status;
     if (!ctx->can_sign)
          return FAIL;
     if (prkey_setup(ctx)) 
          return FAIL;
     
     if ((unsigned)inlen > ((sc_pkcs15_prkey_info_t *)ctx->obj_prkey_sign->data)->modulus_length/8) {
          fprintf(stderr, "Input buffer is too large\n");
          goto fail_sign;
     }
     if (*outlen < 0 || (unsigned)*outlen != ((sc_pkcs15_prkey_info_t *)ctx->obj_prkey_sign->data)->modulus_length/8) {
          fprintf(stderr, "output buffer is too small\n");
          goto fail_sign;
     }
     
     status=sc_pkcs15_compute_signature(ctx->p15card, ctx->obj_prkey_sign, 
                               flags,
			       inbuf, inlen, outbuf, *outlen);
     if (status < 0) {
          fprintf(stderr, "Sign failed: %s\n", sc_strerror(status));
          goto fail_sign;
     }
     *outlen=status;
     return OK;
 fail_sign:
     return FAIL;
}

int p15_simple_sign_raw(p15_simple_t ctx, unsigned char *inbuf, int inlen,
                       unsigned char *outbuf, int *outlen) {
     if (!ctx->can_sign)
          return FAIL;

     return do_sign(ctx, inbuf, inlen, outbuf, outlen,
                    SC_ALGORITHM_RSA_PAD_PKCS1);
}


int p15_simple_sign_md5(p15_simple_t ctx, unsigned char *inbuf, int inlen,
                       unsigned char *outbuf, int *outlen) {
     if (inlen != 16) {
          fprintf(stderr, "Input buffer is wrong size\n");
          return FAIL;
     }
     return do_sign(ctx, inbuf, inlen, outbuf, outlen,
                    SC_ALGORITHM_RSA_PAD_PKCS1|SC_ALGORITHM_RSA_HASH_MD5);
}
int p15_simple_sign_sha(p15_simple_t ctx, unsigned char *inbuf, int inlen,
                       unsigned char *outbuf, int *outlen) {
     if (inlen != 20) {
          fprintf(stderr, "Input buffer is wrong size\n");
          return FAIL;
     }
     return do_sign(ctx, inbuf, inlen, outbuf, outlen,
                    SC_ALGORITHM_RSA_PAD_PKCS1|SC_ALGORITHM_RSA_HASH_SHA1);
}

int p15_simple_sign_tls(p15_simple_t ctx, unsigned char *inbuf, int inlen,
                       unsigned char *outbuf, int *outlen) {
     if (inlen != 36) {
          fprintf(stderr, "Input buffer is wrong size\n");
          return FAIL;
     }
     return do_sign(ctx, inbuf, inlen, outbuf, outlen,
                    SC_ALGORITHM_RSA_PAD_PKCS1|SC_ALGORITHM_RSA_HASH_MD5_SHA1);
}
