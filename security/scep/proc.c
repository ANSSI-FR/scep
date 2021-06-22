// SPDX-License-Identifier: GPL-2.0-only
/*
 * SCEP Linux security module.
 *
 * Author: Nicolas Bouchinet <nicolas.bouchinet@ssi.gouv.fr>
 *
 * Copyright (C) 2021 ANSSI
 */

#include <linux/lsm_hooks.h>

#include "setup.h"
#include "cred.h"
#include "domain.h"

static int scep_getprocattr(struct task_struct *task, char *name, char **value)
{
	if (strcmp(name, "current") != 0)
		return -EINVAL;
	*value = kzalloc(sizeof(char) * D_DOMAIN_ID + 1, GFP_KERNEL);
	if (*value == NULL)
		return -ENOMEM;
	scep_domain_id_to_string(task, *value);
	return D_DOMAIN_ID;
}

static struct security_hook_list scep_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(getprocattr, scep_getprocattr)
};

__init void scep_add_proc_hooks(void)
{
	security_add_hooks(scep_hooks, ARRAY_SIZE(scep_hooks),
			"scep");
}
