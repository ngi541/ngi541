/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#ifndef NGI541_VALIDATION_ACVP_ADAPTER_H
#define NGI541_VALIDATION_ACVP_ADAPTER_H

int ngi541_acvp_adapter_build_probe (void);

int ngi541_acvp_run_offline (
  const char *request_filename,
  const char *response_filename);

#endif /* NGI541_VALIDATION_ACVP_ADAPTER_H */