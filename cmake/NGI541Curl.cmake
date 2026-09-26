include_guard(GLOBAL)

function(ngi541_resolve_acvp_curl out_root)
    set(_curl_root "")

    # -----------------------------------------------------------------------
    # 1. Explicit override.
    #
    # This is an escape hatch for custom toolchains/sysroots. Normal users
    # should not need to specify it.
    # -----------------------------------------------------------------------

    if(NGI541_ACVP_CURL_ROOT)
        set(
            _curl_root
            "${NGI541_ACVP_CURL_ROOT}"
        )
    endif()

    # -----------------------------------------------------------------------
    # 2. On macOS prefer an installed Homebrew curl when available.
    #
    # macOS can expose multiple libcurl installations through the system SDK,
    # curl-config and package managers. Homebrew provides a self-contained
    # prefix suitable for libacvp's --with-libcurl-dir interface.
    # -----------------------------------------------------------------------

    if(NOT _curl_root AND APPLE)
        find_program(
            _ngi541_brew
            NAMES brew
        )

        if(_ngi541_brew)
            execute_process(
                COMMAND
                    "${_ngi541_brew}"
                    --prefix
                    curl

                RESULT_VARIABLE
                    _ngi541_brew_result

                OUTPUT_VARIABLE
                    _ngi541_brew_curl_root

                OUTPUT_STRIP_TRAILING_WHITESPACE

                ERROR_QUIET
            )

            if(
                _ngi541_brew_result EQUAL 0
                AND
                IS_DIRECTORY
                    "${_ngi541_brew_curl_root}"
            )
                set(
                    _curl_root
                    "${_ngi541_brew_curl_root}"
                )
            endif()
        endif()
    endif()

    # -----------------------------------------------------------------------
    # 3. pkg-config.
    #
    # This is normally the most useful path on Linux distributions.
    # -----------------------------------------------------------------------

    if(NOT _curl_root)
        find_package(
            PkgConfig
            QUIET
        )

        if(PkgConfig_FOUND)
            execute_process(
                COMMAND
                    "${PKG_CONFIG_EXECUTABLE}"
                    --variable=prefix
                    libcurl

                RESULT_VARIABLE
                    _ngi541_pkg_result

                OUTPUT_VARIABLE
                    _ngi541_pkg_curl_root

                OUTPUT_STRIP_TRAILING_WHITESPACE

                ERROR_QUIET
            )

            if(
                _ngi541_pkg_result EQUAL 0
                AND
                _ngi541_pkg_curl_root
                AND
                IS_DIRECTORY
                    "${_ngi541_pkg_curl_root}"
            )
                set(
                    _curl_root
                    "${_ngi541_pkg_curl_root}"
                )
            endif()
        endif()
    endif()

    # -----------------------------------------------------------------------
    # 4. curl-config fallback.
    # -----------------------------------------------------------------------

    if(NOT _curl_root)
        find_program(
            _ngi541_curl_config
            NAMES curl-config
        )

        if(_ngi541_curl_config)
            execute_process(
                COMMAND
                    "${_ngi541_curl_config}"
                    --prefix

                RESULT_VARIABLE
                    _ngi541_curl_config_result

                OUTPUT_VARIABLE
                    _ngi541_curl_config_root

                OUTPUT_STRIP_TRAILING_WHITESPACE

                ERROR_QUIET
            )

            if(
                _ngi541_curl_config_result EQUAL 0
                AND
                _ngi541_curl_config_root
                AND
                IS_DIRECTORY
                    "${_ngi541_curl_config_root}"
            )
                set(
                    _curl_root
                    "${_ngi541_curl_config_root}"
                )
            endif()
        endif()
    endif()

    # -----------------------------------------------------------------------
    # 5. Final CMake discovery fallback.
    #
    # If CMake can find CURL but no prefix-oriented tool above is available,
    # derive a prefix from an include directory.
    # -----------------------------------------------------------------------

    if(NOT _curl_root)
        find_package(
            CURL
            QUIET
        )

        if(CURL_FOUND)
            foreach(_ngi541_curl_include IN LISTS CURL_INCLUDE_DIRS)
                if(
                    _ngi541_curl_include
                    MATCHES
                    "^(.+)/include(/.*)?$"
                )
                    set(
                        _curl_root
                        "${CMAKE_MATCH_1}"
                    )

                    break()
                endif()
            endforeach()
        endif()
    endif()

    if(NOT _curl_root)
        message(
            FATAL_ERROR
            "Unable to locate libcurl for the online ACVP build. "
            "Install the libcurl development package or set "
            "NGI541_ACVP_CURL_ROOT as an override."
        )
    endif()

    # -----------------------------------------------------------------------
    # Resolve a CMake CURL target as well.
    #
    # libacvp uses the prefix through --with-libcurl-dir. NGI541 uses the
    # imported target to propagate the corresponding link dependency to the
    # final executable.
    # -----------------------------------------------------------------------

    set(
        CURL_ROOT
        "${_curl_root}"
    )

    find_package(
        CURL
        REQUIRED
    )

    if(NOT TARGET CURL::libcurl)
        message(
            FATAL_ERROR
            "libcurl was detected but CURL::libcurl is unavailable"
        )
    endif()

    message(
        STATUS
        "NGI541 ACVP online libcurl root: ${_curl_root}"
    )

    set(
        ${out_root}
        "${_curl_root}"
        PARENT_SCOPE
    )
endfunction()