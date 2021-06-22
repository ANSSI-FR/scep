/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SCEP Linux security module.
 *
 * Author: Nicolas Bouchinet <nicolas.bouchinet@ssi.gouv.fr>
 * Author: Vincent Dagonneau <vincent.dagonneau@ssi.gouv.fr>
 *
 * Copyright (C) 2021 ANSSI
 */

#ifndef _SECURITY_SCEP_DOMAIN_H
#define _SECURITY_SCEP_DOMAIN_H

#include <crypto/blake2s.h>

#define D_DOMAIN_ID (BLAKE2S_HASH_SIZE * 2)

void scep_update_domain(struct task_struct *const task, struct cred *const new);
bool scep_is_same_domain(const struct task_struct *const task1,
							const struct task_struct *const task2);

#endif /* _SECURITY_SCEP_DOMAIN_H */
