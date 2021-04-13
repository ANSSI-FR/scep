// SPDX-License-Identifier: GPL-2.0-only
/*
 * VServer Linux security module.
 *
 * Author: Nicolas Bouchinet <nicolas.bouchinet@ssi.gouv.fr>
 * Author: Vincent Dagonneau <vincent.dagonneau@ssi.gouv.fr>
 *
 * Copyright (C) 2021 ANSSI
 */

#ifndef _SECURITY_VSERVER_PTRACE_H
#define _SECURITY_VSERVER_PTRACE_H

__init void vserver_add_ptrace_hooks(void);

#endif /* _SECURITY_VSERVER_PTRACE_H */