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

#include "common.h"
#include "setup.h"

struct vserver_cred_security {
	u8 domain_id[BLAKE2S_HASH_SIZE];
};

static inline struct vserver_cred_security *vserver_cred(
		const struct cred *cred)
{
	return cred->security + vserver_blob_sizes.lbs_cred;
}

/*
 * TODO: The caller must also make sure task doesn't get deleted, either by holding a
 * ref on task or by holding tasklist_lock to prevent it from being unlinked.
 */
static inline void vserver_domain_id_to_string(const struct task_struct *const task, char *sdomain_id)
{
	size_t len;
	const u8 *domain_id;

	BUG_ON(!sdomain_id || !task);
	// Get cred with read_rcu_lock.
	domain_id = vserver_cred(get_task_cred(task))->domain_id;
	for (len = 0; len < BLAKE2S_HASH_SIZE; len++) {
		sdomain_id += sprintf(sdomain_id, "%02x", domain_id[len]);
	}
}

__init void vserver_add_cred_hooks(void);

#endif /* _SECURITY_vserver_CRED_H */
