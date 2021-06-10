// SPDX-License-Identifier: GPL-2.0-only
/*
 * VServer Linux security module.
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

uuid_t VSERVER_RUNTIME_SALT;

struct lsm_blob_sizes vserver_blob_sizes __lsm_ro_after_init = {
	.lbs_cred = sizeof(struct vserver_cred_security),
};

static int __init vserver_init(void)
{
	vserver_add_cred_hooks();
	vserver_add_ptrace_hooks();
	vserver_add_proc_hooks();
	uuid_gen(&VSERVER_RUNTIME_SALT);
	pr_info("Up and running.\n");
	return 0;
}

DEFINE_LSM(vserver) = {
	.name = "vserver",
	.init = vserver_init,
	.blobs = &vserver_blob_sizes,
};
