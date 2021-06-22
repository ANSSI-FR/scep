/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SCEP Linux security module.
 *
 * Author: Nicolas Bouchinet <nicolas.bouchinet@ssi.gouv.fr>
 *
 * Copyright (C) 2021 ANSSI
 */

#ifndef _SECURITY_SCEP_PROC_H
#define _SECURITY_SCEP_PROC_H

#include <linux/init.h>

#include "setup.h"

__init void scep_add_proc_hooks(void);

#endif /* _SECURITY_SCEP_PROC_H */
