// SPDX-License-Identifier: GPL-2.0-only
/*
 * VServer Linux security module.
 *
 * Author: Nicolas Bouchinet <nicolas.bouchinet@ssi.gouv.fr>
 * Author: Vincent Dagonneau <vincent.dagonneau@ssi.gouv.fr>
 *
 * Copyright (C) 2021 ANSSI
 */

#ifndef _SECURITY_VSERVER_DOMAIN_H
#define _SECURITY_VSERVER_DOMAIN_H

void vserver_update_domain(struct task_struct *const task);
bool vserver_is_same_domain(const struct task_struct *const task1,
							const struct task_struct *const task2);

#endif /* _SECURITY_vserver_DOMAIN_H */