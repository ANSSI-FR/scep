// SPDX-License-Identifier: GPL-2.0-only
/*
 * VServer Linux security module.
 *
 * Author: Nicolas Bouchinet <nicolas.bouchinet@ssi.gouv.fr>
 * Author: Vincent Dagonneau <vincent.dagonneau@ssi.gouv.fr>
 *
 * Copyright (C) 2021 ANSSI
 */

#include <linux/lsm_hooks.h>

#include "domain.h"

static int vserver_ptrace_access_check(struct task_struct *child,
				    unsigned int mode)
{
	if (!vserver_is_same_domain(current, child))
		return -EPERM;

	return 0;
}

static int vserver_ptrace_traceme(struct task_struct *parent)
{
	return 0;
}

static struct security_hook_list vserver_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(ptrace_access_check, vserver_ptrace_access_check),
	LSM_HOOK_INIT(ptrace_traceme, vserver_ptrace_traceme),
};

__init void vserver_add_ptrace_hooks(void)
{
	security_add_hooks(vserver_hooks, ARRAY_SIZE(vserver_hooks), "vserver");
}
