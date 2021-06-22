// SPDX-License-Identifier: GPL-2.0-only
/*
 * SCEP Linux security module.
 *
 * Author: Nicolas Bouchinet <nicolas.bouchinet@ssi.gouv.fr>
 * Author: Vincent Dagonneau <vincent.dagonneau@ssi.gouv.fr>
 *
 * Copyright (C) 2021 ANSSI
 */

#include <linux/cgroup.h>
#include <linux/uuid.h>

#include <crypto/blake2s.h>
#include <crypto/algapi.h>

#include "setup.h"
#include "cred.h"
#include "common.h"

/*
 * @TODO: The caller must also make sure task doesn't get deleted, either by holding a
 * ref on task or by holding tasklist_lock to prevent it from being unlinked.
 * @TODO: Spinlock the task cred write since it is rcu backed.
 */
void scep_update_domain(struct task_struct *const task, struct cred *const new)
{
	struct blake2s_state blake;

	blake2s_init(&blake, BLAKE2S_HASH_SIZE);
	blake2s_update(&blake, SCEP_RUNTIME_SALT.b, UUID_SIZE);
	//
	blake2s_update(&blake, (const u8 *)new->user_ns, sizeof(struct user_namespace *));
	//@TODO: RCU sur cgroups
	blake2s_update(&blake, (const u8 *)task->cgroups->dfl_cgrp, sizeof(struct cgroup *));
	blake2s_final(&blake, scep_cred(new)->domain_id);
}

bool scep_is_same_domain(const struct task_struct *const task1,
							const struct task_struct *const task2)
{
	return !crypto_memneq(
		scep_cred(get_task_cred(task1))->domain_id,
		scep_cred(get_task_cred(task2))->domain_id,
		BLAKE2S_HASH_SIZE
	);
}
