// SPDX-License-Identifier: GPL-2.0-only
/*
 * VServer Linux security module.
 *
 * Author: Nicolas Bouchinet <nicolas.bouchinet@ssi.gouv.fr>
 * Author: Vincent Dagonneau <vincent.dagonneau@ssi.gouv.fr>
 *
 * Copyright (C) 2021 ANSSI
 */

#include <linux/cred.h>
#include <linux/lsm_hooks.h>

#include "cred.h"
#include "domain.h"

static int hook_cred_prepare(struct cred *const new,
		const struct cred *const old, const gfp_t gfp)
{
	vserver_update_domain(current);
	return 0;
}

static void hook_cred_free(struct cred *const cred)
{
}

static struct security_hook_list vserver_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(cred_prepare, hook_cred_prepare),
	LSM_HOOK_INIT(cred_free, hook_cred_free),
};

__init void vserver_add_cred_hooks(void)
{
	security_add_hooks(vserver_hooks, ARRAY_SIZE(vserver_hooks),
			"vserver");
}
