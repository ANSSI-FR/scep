/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SCEP Linux security module.
 *
 * Author: Nicolas Bouchinet <nicolas.bouchinet@ssi.gouv.fr>
 * Author: Vincent Dagonneau <vincent.dagonneau@ssi.gouv.fr>
 *
 * Copyright (C) 2021 ANSSI
 */

#ifndef _SECURITY_SCEP_COMMON_H
#define _SECURITY_SCEP_COMMON_H

#define SCEP_NAME "scep"

#ifdef pr_fmt
#undef pr_fmt
#endif

#define pr_fmt(fmt) "%s:%s: " fmt, SCEP_NAME, __func__

#endif /* _SECURITY_SCEP_COMMON_H */
