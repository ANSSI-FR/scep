/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SCEP Linux security module.
 *
 * Author: Nicolas Bouchinet <nicolas.bouchinet@ssi.gouv.fr>
 * Author: Vincent Dagonneau <vincent.dagonneau@ssi.gouv.fr>
 *
 * Copyright (C) 2021 ANSSI
 */

#ifndef _SECURITY_SCEP_PTRACE_H
#define _SECURITY_SCEP_PTRACE_H

__init void scep_add_ptrace_hooks(void);

#endif /* _SECURITY_SCEP_PTRACE_H */
