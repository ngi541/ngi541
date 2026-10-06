/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#ifndef NGI541_ENGINE_H
#define NGI541_ENGINE_H

#include <ngi541/api.h>
#include <ngi541/crypto.h>
#include <ngi541/prepared.h>

NGI541_BEGIN_DECLS

/*
 * Initializes the NGI541 execution engine.
 *
 * Initialization selects the available native implementations for
 * the current execution environment.
 *
 * The function may be called more than once. Repeated successful
 * initialization returns NGI541_STATUS_OK.
 *
 * Cryptographic execution functions require successful initialization.
 */
NGI541_API ngi541_status_t
ngi541_engine_init (void);

NGI541_END_DECLS

#endif /* NGI541_ENGINE_H */