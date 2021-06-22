// SPDX-License-Identifier: GPL-2.0-only
/*
 * VServer Linux security module.
 *
 * Author: Nicolas Bouchinet <nicolas.bouchinet@ssi.gouv.fr>
 *
 * Copyright (C) 2021 ANSSI
 */

#include <linux/lsm_hooks.h>

#include "setup.h"
#include "cred.h"
#include "domain.h"

static int vserver_getprocattr(struct task_struct *task, char *name, char **value)
{
	if (strcmp(name, "current") != 0)
		return -EINVAL;
	*value = kzalloc(sizeof(char) * D_DOMAIN_ID + 1, GFP_KERNEL);
	if (*value == NULL)
		return -ENOMEM;
	vserver_domain_id_to_string(task, *value);
	return D_DOMAIN_ID;
}

static struct security_hook_list vserver_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(getprocattr, vserver_getprocattr)
};

__init void vserver_add_proc_hooks(void)
{
	security_add_hooks(vserver_hooks, ARRAY_SIZE(vserver_hooks),
			"vserver");
}
