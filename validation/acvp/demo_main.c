/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#define _POSIX_C_SOURCE 200809L

#include "registrations/profile_v1.h"

#include <acvp/acvp.h>
#include <ngi541/engine.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>


#define NGI541_ACVTS_SERVER "demo.acvts.nist.gov"
#define NGI541_ACVTS_PORT 443
#define NGI541_ACVTS_PATH_SEGMENT "/acvp/v1/"
#define NGI541_ACVTS_API_CONTEXT "acvp/"

#define NGI541_TOTP_SEED_MAX 64

typedef struct
{
  const char *cli_name;
  const char *display_name;
  unsigned int profile_mask;
} ngi541_demo_algorithm_t;


static const ngi541_demo_algorithm_t
ngi541_demo_algorithms[] =
{
  {
    "all",
    "full profile",
    NGI541_ACVP_PROFILE_V1_ALL
  },
  {
    "sha2-256",
    "SHA2-256",
    NGI541_ACVP_PROFILE_SHA2_256
  },
  {
    "sha2-224",
    "SHA2-224",
    NGI541_ACVP_PROFILE_SHA2_224
  },
  {
    "aes-cbc",
    "AES-CBC",
    NGI541_ACVP_PROFILE_AES_CBC
  },
  {
    "aes-ctr",
    "AES-CTR",
    NGI541_ACVP_PROFILE_AES_CTR
  },
  {
    "aes-gcm",
    "AES-GCM",
    NGI541_ACVP_PROFILE_AES_GCM
  }
};


/*
 * This implementation is provided by the pinned libacvp application
 * sources:
 *
 *   third_party/libacvp/app/totp/totp.c
 *
 * It consumes ACV_TOTP_SEED from the process environment and generates
 * the 8-digit SHA-256 TOTP expected by ACVTS.
 */
ACVP_RESULT totp (
  char **token,
  int token_max);


typedef struct
{
  const char *cert_file;
  const char *key_file;
  const char *totp_seed_file;
  const char *session_dir;
  const char *ca_file;

  const ngi541_demo_algorithm_t *algorithm;

  int dry_run;
  int non_sample;
} ngi541_demo_options_t;


static void
secure_zero (
  void *ptr,
  size_t len)
{
  volatile unsigned char *p =
    (volatile unsigned char *) ptr;

  while (len > 0)
    {
      *p++ = 0;
      --len;
    }
}

static const ngi541_demo_algorithm_t *
find_algorithm (
  const char *name)
{
  size_t i;

  for (i = 0;
       i < sizeof (ngi541_demo_algorithms) /
             sizeof (ngi541_demo_algorithms[0]);
       ++i)
    {
      if (strcmp (
            name,
            ngi541_demo_algorithms[i].cli_name) == 0)
        return &ngi541_demo_algorithms[i];
    }

  return NULL;
}


static void
print_usage (
  const char *program)
{
  fprintf (
    stderr,
    "  %s --dry-run --algorithm <algorithm>\n"
    "\n"
    "  %s \\\n"
    "    --algorithm <algorithm> \\\n"
    "    --cert <client-cert.pem> \\\n"
    "    --key <private-key.pem> \\\n"
    "    --totp-seed-file <seed-file> \\\n"
    "    --session-dir <directory> \\\n"
    "    [--ca-file <ca-bundle.pem>]\n"
    "\n"
    "algorithms:\n"
    "  sha2-256\n"
    "  sha2-224\n"
    "  aes-cbc\n"
    "  aes-ctr\n"
    "  aes-gcm\n"
    "\n"
    "Live sessions are sample by default.\n"
    "Use --non-sample for a non-sample ACVTS Demo session.\n",
    program,
    program);
}


static int
parse_options (
  int argc,
  char **argv,
  ngi541_demo_options_t *options)
{
  int i;

  memset (
    options,
    0,
    sizeof (*options));

  for (i = 1; i < argc; ++i)
    {
      if (strcmp (
            argv[i],
            "--dry-run") == 0)
        {
          options->dry_run = 1;
        }
        else if (strcmp (
                argv[i],
                "--non-sample") == 0)
        {
            options->non_sample = 1;
        }
      else if (strcmp (
                 argv[i],
                 "--algorithm") == 0)
        {
          if (++i >= argc)
            return 1;

          options->algorithm =
            find_algorithm (
              argv[i]);

          if (options->algorithm == NULL)
            {
              fprintf (
                stderr,
                "unsupported algorithm: %s\n",
                argv[i]);

              return 1;
            }
        }
      else if (strcmp (
                 argv[i],
                 "--cert") == 0)
        {
          if (++i >= argc)
            return 1;

          options->cert_file =
            argv[i];
        }
      else if (strcmp (
                 argv[i],
                 "--key") == 0)
        {
          if (++i >= argc)
            return 1;

          options->key_file =
            argv[i];
        }
      else if (strcmp (
                 argv[i],
                 "--totp-seed-file") == 0)
        {
          if (++i >= argc)
            return 1;

          options->totp_seed_file =
            argv[i];
        }
      else if (strcmp (
                 argv[i],
                 "--session-dir") == 0)
        {
          if (++i >= argc)
            return 1;

          options->session_dir =
            argv[i];
        }
      else if (strcmp (
                 argv[i],
                 "--ca-file") == 0)
        {
          if (++i >= argc)
            return 1;

          options->ca_file =
            argv[i];
        }
      else
        {
          fprintf (
            stderr,
            "unknown argument: %s\n",
            argv[i]);

          return 1;
        }
    }

  if (options->algorithm == NULL)
    return 1;

  if (options->dry_run)
    return 0;

  if (options->cert_file == NULL ||
      options->key_file == NULL ||
      options->totp_seed_file == NULL ||
      options->session_dir == NULL)
    return 1;

  return 0;
}


static int
check_readable_file (
  const char *path,
  const char *label)
{
  if (access (path, R_OK) != 0)
    {
      fprintf (
        stderr,
        "%s is not readable: %s\n",
        label,
        path);

      return 1;
    }

  return 0;
}


static int
check_session_directory (
  const char *path)
{
  struct stat st;

  if (stat (path, &st) != 0)
    {
      fprintf (
        stderr,
        "unable to stat session directory '%s': %s\n",
        path,
        strerror (errno));

      return 1;
    }

  if (!S_ISDIR (st.st_mode))
    {
      fprintf (
        stderr,
        "session path is not a directory: %s\n",
        path);

      return 1;
    }

  return 0;
}


static int
read_totp_seed (
  const char *path,
  char *seed,
  size_t seed_size)
{
  FILE *fp;
  size_t len;
  int extra;

  fp =
    fopen (
      path,
      "rb");

  if (fp == NULL)
    {
      fprintf (
        stderr,
        "unable to open TOTP seed file\n");

      return 1;
    }

  len =
    fread (
      seed,
      1,
      seed_size - 1,
      fp);

  if (ferror (fp))
    {
      fprintf (
        stderr,
        "unable to read TOTP seed file\n");

      fclose (fp);
      return 1;
    }

  /*
   * Detect a seed that does not fit into our bounded buffer.
   */
  extra =
    fgetc (fp);

  if (extra != EOF)
    {
      fprintf (
        stderr,
        "TOTP seed exceeds supported length\n");

      fclose (fp);
      return 1;
    }

  fclose (fp);

  /*
   * Strip only line terminators introduced by the text file.
   * Do not otherwise transform the Base64 value supplied by NIST.
   */
  while (len > 0 &&
         (seed[len - 1] == '\n' ||
          seed[len - 1] == '\r'))
    --len;

  if (len == 0 ||
      len > NGI541_TOTP_SEED_MAX)
    {
      fprintf (
        stderr,
        "invalid TOTP seed length\n");

      return 1;
    }

  seed[len] = '\0';

  /*
   * Embedded CR/LF is invalid. Do not print the secret.
   */
  for (size_t i = 0; i < len; ++i)
    {
      if (seed[i] == '\n' ||
          seed[i] == '\r')
        {
          fprintf (
            stderr,
            "invalid line break inside TOTP seed\n");

          secure_zero (
            seed,
            seed_size);

          return 1;
        }
    }

  return 0;
}


static int
create_session_context (
  ACVP_CTX **ctx,
  const ngi541_demo_algorithm_t *algorithm,
  int is_sample)
{
  ACVP_RESULT result;

  if (ctx == NULL ||
      algorithm == NULL)
    return 1;

  result =
    acvp_create_test_session (
      ctx,
      NULL,
      ACVP_LOG_LVL_INFO);

  if (result != ACVP_SUCCESS)
    {
      fprintf (
        stderr,
        "acvp_create_test_session failed: %s\n",
        acvp_lookup_error_string (result));

      return 1;
    }

  result =
    ngi541_acvp_register_profile_v1_selected (
      *ctx,
      algorithm->profile_mask);

  if (result != ACVP_SUCCESS)
    {
      fprintf (
        stderr,
        "%s registration failed: %s\n",
        algorithm->display_name,
        acvp_lookup_error_string (result));

      return 1;
    }

  /*
   * ACVTS uses isSample=false by default.
   *
   * Only explicitly mark the session when sample behavior
   * is requested.
   */
  if (is_sample)
    {
      result =
        acvp_mark_as_sample (
          *ctx);

      if (result != ACVP_SUCCESS)
        {
          fprintf (
            stderr,
            "unable to mark %s session as sample: %s\n",
            algorithm->display_name,
            acvp_lookup_error_string (result));

          return 1;
        }
    }

  return 0;
}


static int
run_dry_registration (
  const ngi541_demo_algorithm_t *algorithm,
  int is_sample)
{
  ACVP_CTX *ctx = NULL;
  ACVP_RESULT result;
  char *registration = NULL;
  int rc = 1;

if (create_session_context (
      &ctx,
      algorithm,
      is_sample) != 0)
    goto cleanup;

  registration =
    acvp_get_current_registration (
      ctx,
      NULL);

  if (registration == NULL)
    {
        fprintf (
        stderr,
        "unable to serialize %s %s registration\n",
        algorithm->display_name,
        is_sample ? "sample" : "non-sample");

      goto cleanup;
    }

  printf (
    "%s\n",
    registration);

  rc = 0;

cleanup:

  free (registration);

  if (ctx != NULL)
    {
      result =
        acvp_free_test_session (
          ctx);

      if (result != ACVP_SUCCESS &&
          rc == 0)
        rc = 1;
    }

  return rc;
}


int
main (
  int argc,
  char **argv)
{
  ngi541_demo_options_t options;

  ACVP_CTX *ctx = NULL;
  ACVP_RESULT result;
  ACVP_RESULT free_result;

  ngi541_status_t engine_status;

  char totp_seed[
    NGI541_TOTP_SEED_MAX + 2] = {0};

  int rc = 1;
  int totp_env_set = 0;
  int session_env_set = 0;
  int is_sample;


  if (parse_options (
        argc,
        argv,
        &options) != 0)
    {
      print_usage (
        argv[0]);

      return 64;
    }

    is_sample =
    options.non_sample ? 0 : 1;

/*
 * This mode performs no network communication and touches no
 * credentials. It is the final registration gate before a
 * live ACVTS submission for the selected algorithm.
 */
if (options.dry_run)
  return
    run_dry_registration (
      options.algorithm,
      is_sample);


  if (check_readable_file (
        options.cert_file,
        "client certificate") != 0 ||
      check_readable_file (
        options.key_file,
        "private key") != 0 ||
      check_readable_file (
        options.totp_seed_file,
        "TOTP seed file") != 0 ||
      check_session_directory (
        options.session_dir) != 0)
    return 65;


  if (options.ca_file != NULL &&
      check_readable_file (
        options.ca_file,
        "CA file") != 0)
    return 65;


  /*
   * Protect any test-session state written by libacvp.
   */
  umask (0077);


  if (read_totp_seed (
        options.totp_seed_file,
        totp_seed,
        sizeof (totp_seed)) != 0)
    goto cleanup;


  /*
   * Upstream libacvp v2.3.1's TOTP callback obtains the Base64 seed
   * from ACV_TOTP_SEED.
   *
   * The user never places the secret in the shell command line.
   */
  if (setenv (
        "ACV_TOTP_SEED",
        totp_seed,
        1) != 0)
    {
      fprintf (
        stderr,
        "unable to configure TOTP environment\n");

      goto cleanup;
    }

  totp_env_set = 1;


  /*
   * Keep libacvp test-session state outside the source/build tree.
   */
  if (setenv (
        "ACV_SESSION_SAVE_PATH",
        options.session_dir,
        1) != 0)
    {
      fprintf (
        stderr,
        "unable to configure ACVP session directory\n");

      goto cleanup;
    }

  session_env_set = 1;


  engine_status =
    ngi541_engine_init ();

  if (engine_status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "NGI541 engine initialization failed: %d\n",
        engine_status);

      goto cleanup;
    }


    if (create_session_context (
        &ctx,
        options.algorithm,
        is_sample) != 0)
    goto cleanup;


  result =
    acvp_set_server (
      ctx,
      NGI541_ACVTS_SERVER,
      NGI541_ACVTS_PORT);

  if (result != ACVP_SUCCESS)
    {
      fprintf (
        stderr,
        "acvp_set_server failed: %s\n",
        acvp_lookup_error_string (result));

      goto cleanup;
    }


  result =
    acvp_set_path_segment (
      ctx,
      NGI541_ACVTS_PATH_SEGMENT);

  if (result != ACVP_SUCCESS)
    {
      fprintf (
        stderr,
        "acvp_set_path_segment failed: %s\n",
        acvp_lookup_error_string (result));

      goto cleanup;
    }


  result =
    acvp_set_api_context (
      ctx,
      NGI541_ACVTS_API_CONTEXT);

  if (result != ACVP_SUCCESS)
    {
      fprintf (
        stderr,
        "acvp_set_api_context failed: %s\n",
        acvp_lookup_error_string (result));

      goto cleanup;
    }


  /*
   * The current NIST Demo endpoint uses a publicly trusted DigiCert
   * chain. Therefore the normal libcurl trust store is used by
   * default.
   *
   * --ca-file is retained only as an explicit override.
   */
  if (options.ca_file != NULL)
    {
      result =
        acvp_set_cacerts (
          ctx,
          options.ca_file);

      if (result != ACVP_SUCCESS)
        {
          fprintf (
            stderr,
            "acvp_set_cacerts failed: %s\n",
            acvp_lookup_error_string (result));

          goto cleanup;
        }
    }


  result =
    acvp_set_certkey (
      ctx,
      (char *) options.cert_file,
      (char *) options.key_file);

  if (result != ACVP_SUCCESS)
    {
      fprintf (
        stderr,
        "acvp_set_certkey failed: %s\n",
        acvp_lookup_error_string (result));

      goto cleanup;
    }


  result =
    acvp_set_2fa_callback (
      ctx,
      &totp);

  if (result != ACVP_SUCCESS)
    {
      fprintf (
        stderr,
        "acvp_set_2fa_callback failed: %s\n",
        acvp_lookup_error_string (result));

      goto cleanup;
    }


    fprintf (
    stderr,
    "NGI541 ACVTS Demo: starting %s %s session\n",
    options.algorithm->display_name,
    is_sample ? "sample" : "non-sample");


  /*
   * fips_validation = 0:
   *
   * This is an ACVP algorithm-validation session, not a CMVP/FIPS
   * module-validation registration.
   *
   * acvp_run() performs the live login/register/download/process/
   * upload/validate workflow.
   */
  result =
    acvp_run (
      ctx,
      0);

  if (result != ACVP_SUCCESS)
    {
        fprintf (
        stderr,
        "ACVTS %s %s session failed: %s\n",
        options.algorithm->display_name,
        is_sample ? "sample" : "non-sample",
        acvp_lookup_error_string (result));

      goto cleanup;
    }


    fprintf (
    stderr,
    "NGI541 ACVTS Demo: %s %s session completed successfully\n",
    options.algorithm->display_name,
    is_sample ? "sample" : "non-sample");

  rc = 0;


cleanup:

  if (ctx != NULL)
    {
      free_result =
        acvp_free_test_session (
          ctx);

      if (free_result != ACVP_SUCCESS)
        {
          fprintf (
            stderr,
            "ACVP context cleanup failed: %s\n",
            acvp_lookup_error_string (free_result));

          if (rc == 0)
            rc = 1;
        }
    }


  if (totp_env_set)
    unsetenv (
      "ACV_TOTP_SEED");

  if (session_env_set)
    unsetenv (
      "ACV_SESSION_SAVE_PATH");


  secure_zero (
    totp_seed,
    sizeof (totp_seed));


  return rc;
}