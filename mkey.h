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
#define MKEY_OP_ENCRYPT     0
#define MKEY_OP_DECRYPT     1
#define MKEY_OP_ADD_KEY     2
#define MKEY_OP_REMOVE_KEY  3
#define MKEY_OP_LIST_KEYS   4
#define MKEY_OP_LIST_TAG    5
#define MKEY_OP_SHUTDOWN    6

#define MKEY_SOCKET         "/var/run/mkey.sock"  /* socket filename */
#define MKEY_FACILITY       LOG_LOCAL1            /* syslog facility */
#define MKEY_MAXSIZE        4096
#define MKEY_HDRSIZE        8
