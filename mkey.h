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
 * General definitions
 */

/* protocol opcodes */
#define MKEY_OP_ENCRYPT             0
#define MKEY_OP_DECRYPT             1
#define MKEY_OP_ADD_KEY             2
#define MKEY_OP_REMOVE_KEY          3
#define MKEY_OP_LIST_KEYS           4
#define MKEY_OP_LIST_TAG            5
#define MKEY_OP_SHUTDOWN            6
#define MKEY_OP_VERIFY_KEY          7
#define MKEY_OP_GENERATE_KEY        8
#define MKEY_OP_GET_METAKEY_INFO    9
#define MKEY_OP_UNSEAL_KEYS        10
#define MKEY_OP_SET_METAKEY        11
#define MKEY_OP_STRING_TO_ETYPE    12
#define MKEY_OP_ETYPE_TO_STRING    13
#define MKEY_OP_STORE_KEYS         14
#define MKEY_OP_LOAD_KEYS          15

#define MKEY_KU_META 0x4D4B6579
#define MKEY_KU_CHAL 0x4D4B4368

#define MKEY_MSTATE_NEW             0  /* no sealed keys; mkey not set */
#define MKEY_MSTATE_OPEN            1  /* no sealed keys; mkey set */
#define MKEY_MSTATE_SEALED          2  /* sealed keys */
#define MKEY_MSTATE_LOADING         3  /* loading data */

#ifdef USE_DOORS
#define MKEY_SOCKET         "/var/run/mkey_door"  /* socket filename */
#else
#define MKEY_SOCKET         "/var/run/mkey.sock"  /* socket filename */
#endif
#define MKEY_RELAY_PORT     1357                  /* TCP port for relay */
#define MKEY_FACILITY       LOG_LOCAL1            /* syslog facility */
#define MKEY_MAXSIZE        4096
#define MKEY_HDRSIZE        8

extern MKey_Error _mkey_encode(void *, int *, MKey_Integer, MKey_Integer,
                               int, MKey_Integer *, MKey_DataBlock *, char *);
extern MKey_Error _mkey_decode_header(void *, int,
                                      MKey_Integer *, MKey_Integer *);
extern MKey_Error _mkey_decode(void *, int, int, MKey_Integer *,
                               MKey_Integer *, MKey_KeyInfo *,
                               MKey_DataBlock *, char **);
extern MKey_Error _mkey_do_request(MKey_Integer, char *, int,
                                   char *, int *, char **);
