// SPDX-License-Identifier: GPL-2.0-only
/*
 * VServer Linux security module.
 *
 * Author: Nicolas Bouchinet <nicolas.bouchinet@ssi.gouv.fr>
 * Author: Vincent Dagonneau <vincent.dagonneau@ssi.gouv.fr>
 *
 * Copyright (C) 2021 ANSSI
 */

#ifndef _SECURITY_VSERVER_SETUP_H
#define _SECURITY_VSERVER_SETUP_H

#include <linux/lsm_hooks.h>

extern uuid_t VSERVER_RUNTIME_SALT;
extern struct lsm_blob_sizes vserver_blob_sizes;

#endif /* _SECURITY_VSERVER_SETUP_H */
