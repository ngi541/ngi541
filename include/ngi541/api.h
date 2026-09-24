/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#ifndef NGI541_API_H
#define NGI541_API_H

#if defined(_WIN32)
#define NGI541_API
#elif defined(__GNUC__) || defined(__clang__)
#define NGI541_API __attribute__ ((visibility ("default")))
#else
#define NGI541_API
#endif

#ifdef __cplusplus
#define NGI541_BEGIN_DECLS extern "C" {
#define NGI541_END_DECLS }
#else
#define NGI541_BEGIN_DECLS
#define NGI541_END_DECLS
#endif

#endif /* NGI541_API_H */