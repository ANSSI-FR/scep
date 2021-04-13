// SPDX-License-Identifier: GPL-2.0-only
/*
 * VServer Linux security module.
 *
 * Author: Nicolas Bouchinet <nicolas.bouchinet@ssi.gouv.fr>
 * Author: Vincent Dagonneau <vincent.dagonneau@ssi.gouv.fr>
 *
 * Copyright (C) 2021 ANSSI
 */

#ifndef _SECURITY_VSERVER_CRED_H
#define _SECURITY_VSERVER_CRED_H

#include <linux/cred.h>
#include <linux/init.h>
#include <crypto/blake2s.h>

#include "setup.h"

struct vserver_cred_security {
	u8 domain_id[BLAKE2S_HASH_SIZE];
};

static inline struct vserver_cred_security *vserver_cred(
		const struct cred *cred)
{
	return cred->security + vserver_blob_sizes.lbs_cred;
}

__init void vserver_add_cred_hooks(void);

#endif /* _SECURITY_vserver_CRED_H */
