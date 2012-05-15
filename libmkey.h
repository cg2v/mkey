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
 * libmkey.h - mkey library header
 */

#include <sys/types.h>

typedef int32_t MKey_Error;
typedef int32_t MKey_Integer;
typedef struct {
  MKey_Integer size;
  void *data;
} MKey_DataBlock;

typedef struct {
  MKey_Integer kvno;
  MKey_Integer enctype;
} MKey_KeyInfo;


extern MKey_Error mkey_encrypt(char *tag, MKey_Integer kvno, 
                               MKey_DataBlock *in, MKey_DataBlock *out);
extern MKey_Error mkey_decrypt(char *tag, MKey_Integer kvno, 
                               MKey_DataBlock *in, MKey_DataBlock *out);

extern MKey_Error mkey_add_key(char *tag, MKey_Integer kvno,
                               MKey_Integer enctype, MKey_DataBlock *key);
extern MKey_Error mkey_remove_key(char *tag, MKey_Integer kvno);
extern MKey_Error mkey_verify_key(char *tag, MKey_Integer kvno);
extern MKey_Error mkey_find_largest_kvno(char *tag, MKey_Integer *kvno);
extern MKey_Error mkey_list_keys(char *tag, MKey_Integer *nkeys, MKey_KeyInfo *keys);
extern MKey_Error mkey_list_tag(MKey_Integer tagid, char *tag, int bufsize);

extern MKey_Error mkey_generate_key(MKey_Integer enctype, MKey_DataBlock *key);
extern MKey_Error mkey_string_to_enctype(char *name, MKey_Integer *enctype);
extern MKey_Error mkey_enctype_to_string(MKey_Integer enctype, char *name, int bufsize);

extern MKey_Error mkey_get_metakey_info(char *tag, MKey_Integer *state,
                                        MKey_Integer *kvno, MKey_Integer *enctype);
extern MKey_Error mkey_unseal_keys(char *tag, MKey_Integer enctype, MKey_DataBlock *key);
extern MKey_Error mkey_set_metakey(char *tag, MKey_Integer kvno,
                                   MKey_Integer enctype, MKey_DataBlock *key);
extern MKey_Error mkey_store_keys(char *tag);
extern MKey_Error mkey_load_keys(char *tag);

extern MKey_Error mkey_shutdown(void);

extern void mkey_set_socket_name(char *);
