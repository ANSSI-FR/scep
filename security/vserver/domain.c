#include <linux/cgroup.h>
#include <linux/uuid.h>

#include <crypto/blake2s.h>
#include <crypto/algapi.h>

#include "setup.h"
#include "cred.h"

void vserver_update_domain(struct task_struct *const task)
{
	struct blake2s_state blake;

	blake2s_init(&blake, BLAKE2S_HASH_SIZE);
	blake2s_update(&blake, VSERVER_RUNTIME_SALT.b, UUID_SIZE);
	blake2s_update(&blake, (const u8*) __task_cred(task)->user_ns, sizeof(struct task_struct*));
	//@TODO: RCU sur cgroups
	blake2s_update(&blake, (const u8*) task->cgroups->dfl_cgrp, sizeof(struct cgroup*));
	blake2s_final(&blake, vserver_cred(__task_cred(task))->domain_id);
}

bool vserver_is_same_domain(const struct task_struct *const task1,
							const struct task_struct *const task2)
{
	return crypto_memneq(vserver_cred(__task_cred(task1))->domain_id, vserver_cred(__task_cred(task2))->domain_id, BLAKE2S_HASH_SIZE);
}