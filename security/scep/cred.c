// SPDX-License-Identifier: GPL-2.0-only
/*
 * SCEP Linux security module.
 *
 * Author: Nicolas Bouchinet <nicolas.bouchinet@ssi.gouv.fr>
 * Author: Vincent Dagonneau <vincent.dagonneau@ssi.gouv.fr>
 *
 * Copyright (C) 2021 ANSSI
 */

#include <linux/cred.h>
#include <linux/lsm_hooks.h>

#include "common.h"
#include "cred.h"
#include "domain.h"

static int hook_cred_prepare(struct cred *const new,
		const struct cred *const old, const gfp_t gfp)
{
	scep_update_domain(current, new);

	return 0;
}

static void hook_cred_free(struct cred *const cred)
{
}

static void hook_cred_transfer(struct cred *new, const struct cred *old)
{
}

int hook_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	return 0;
}


int hook_bprm_creds_for_exec(struct linux_binprm *bprm)
{
	return 0;
}

int hook_bprm_creds_from_file(struct linux_binprm *bprm, struct file *file)
{
	return 0;
}

void hook_bprm_committing_creds(struct linux_binprm *bprm)
{
}

void hook_bprm_committed_creds(struct linux_binprm *bprm)
{
}

static struct security_hook_list scep_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(cred_prepare, hook_cred_prepare),
	LSM_HOOK_INIT(cred_free, hook_cred_free),
	LSM_HOOK_INIT(cred_transfer, hook_cred_transfer),
	LSM_HOOK_INIT(cred_alloc_blank, hook_cred_alloc_blank),
	LSM_HOOK_INIT(bprm_creds_for_exec, hook_bprm_creds_for_exec),
	LSM_HOOK_INIT(bprm_creds_from_file, hook_bprm_creds_from_file),
	LSM_HOOK_INIT(bprm_committing_creds, hook_bprm_committing_creds),
	LSM_HOOK_INIT(bprm_committed_creds, hook_bprm_committed_creds),
};

__init void scep_add_cred_hooks(void)
{
	security_add_hooks(scep_hooks, ARRAY_SIZE(scep_hooks),
			"scep");
}
