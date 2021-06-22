/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SCEP Linux security module.
 *
 * Author: Nicolas Bouchinet <nicolas.bouchinet@ssi.gouv.fr>
 * Author: Vincent Dagonneau <vincent.dagonneau@ssi.gouv.fr>
 *
 * Copyright (C) 2021 ANSSI
 */

#ifndef _SECURITY_SCEP_SETUP_H
#define _SECURITY_SCEP_SETUP_H

#include <linux/lsm_hooks.h>

extern uuid_t SCEP_RUNTIME_SALT;
extern struct lsm_blob_sizes scep_blob_sizes;

#endif /* _SECURITY_SCEP_SETUP_H */
