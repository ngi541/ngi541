/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#ifndef NGI541_ENGINE_H
#define NGI541_ENGINE_H

#include <ngi541/api.h>
#include <ngi541/crypto.h>

NGI541_BEGIN_DECLS

/*
 * Initializes the NGI541 execution engine and selects the best
 * available native implementations for the current environment.
 *
 * The function is idempotent. It must complete successfully before
 * cryptographic execution functions are used.
 */
NGI541_API ngi541_status_t
ngi541_engine_init (void);

NGI541_END_DECLS

#endif /* NGI541_ENGINE_H */