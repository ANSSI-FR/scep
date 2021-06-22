// SPDX-License-Identifier: GPL-2.0-only
/*
 * SCEP Linux security module.
 *
 * Author: Nicolas Bouchinet <nicolas.bouchinet@ssi.gouv.fr>
 * Author: Vincent Dagonneau <vincent.dagonneau@ssi.gouv.fr>
 *
 * Copyright (C) 2021 ANSSI
 */

#include <linux/init.h>
#include <linux/lsm_hooks.h>

#include "common.h"
#include "cred.h"
#include "proc.h"
#include "ptrace.h"

uuid_t SCEP_RUNTIME_SALT;

struct lsm_blob_sizes scep_blob_sizes __lsm_ro_after_init = {
	.lbs_cred = sizeof(struct scep_cred_security),
};

static int __init scep_init(void)
{
	scep_add_cred_hooks();
	scep_add_ptrace_hooks();
	scep_add_proc_hooks();
	uuid_gen(&SCEP_RUNTIME_SALT);
	pr_info("Up and running.\n");
	return 0;
}

DEFINE_LSM(scep) = {
	.name = "scep",
	.init = scep_init,
	.blobs = &scep_blob_sizes,
};
