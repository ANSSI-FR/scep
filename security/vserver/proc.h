// SPDX-License-Identifier: GPL-2.0-only
/*
 * VServer Linux security module.
 *
 * Author: Nicolas Bouchinet <nicolas.bouchinet@ssi.gouv.fr>
 *
 * Copyright (C) 2021 ANSSI
 */

#ifndef _SECURITY_VSERVER_PROC_H
#define _SECURITY_VSERVER_PROC_H

#include <linux/init.h>

#include "setup.h"

__init void vserver_add_proc_hooks(void);

#endif /* _SECURITY_vserver_PROC_H */
