include_guard(GLOBAL)


function(ngi541_find_differential_openssl)
    set(_ngi541_explicit_root FALSE)

    if(
        DEFINED OPENSSL_ROOT_DIR
        AND
        NOT "${OPENSSL_ROOT_DIR}" STREQUAL ""
    )
        set(_ngi541_explicit_root TRUE)
    endif()

    # -----------------------------------------------------------------------
    # 1. Standard CMake discovery.
    #
    # This is the normal path on Linux and also supports toolchains,
    # CMAKE_PREFIX_PATH, OPENSSL_ROOT_DIR and other standard CMake hints.
    # -----------------------------------------------------------------------

    find_package(
        OpenSSL 3.0
        QUIET
        COMPONENTS Crypto
    )

    if(TARGET OpenSSL::Crypto)
        if(DEFINED OPENSSL_VERSION)
            set(_ngi541_openssl_version "${OPENSSL_VERSION}")
        elseif(DEFINED OpenSSL_VERSION)
            set(_ngi541_openssl_version "${OpenSSL_VERSION}")
        else()
            set(_ngi541_openssl_version "unknown")
        endif()

        message(
            STATUS
            "NGI541 differential OpenSSL: "
            "${_ngi541_openssl_version}"
        )

        return()
    endif()

    # If the user explicitly selected a root, do not silently replace it
    # with another installation.
    if(_ngi541_explicit_root)
        message(
            FATAL_ERROR
            "NGI541 differential tests require OpenSSL >= 3.0, "
            "but no compatible OpenSSL::Crypto target was found under "
            "OPENSSL_ROOT_DIR='${OPENSSL_ROOT_DIR}'."
        )
    endif()

    # -----------------------------------------------------------------------
    # 2. macOS/Homebrew fallback.
    #
    # Homebrew keeps openssl@3 keg-only on many installations, which means
    # standard CMake discovery may not see it without an explicit prefix.
    # -----------------------------------------------------------------------

    if(APPLE)
        find_program(
            _ngi541_brew
            NAMES brew
        )

        if(_ngi541_brew)
            execute_process(
                COMMAND
                    "${_ngi541_brew}"
                    --prefix
                    openssl@3

                RESULT_VARIABLE
                    _ngi541_brew_result

                OUTPUT_VARIABLE
                    _ngi541_brew_openssl_root

                OUTPUT_STRIP_TRAILING_WHITESPACE

                ERROR_QUIET
            )

            if(
                _ngi541_brew_result EQUAL 0
                AND
                IS_DIRECTORY
                    "${_ngi541_brew_openssl_root}"
            )
                #
                # Remove values potentially cached by the unsuccessful
                # standard FindOpenSSL pass before retrying with the
                # Homebrew prefix.
                #
                unset(OPENSSL_INCLUDE_DIR CACHE)
                unset(OPENSSL_CRYPTO_LIBRARY CACHE)
                unset(OPENSSL_SSL_LIBRARY CACHE)

                set(
                    OPENSSL_ROOT_DIR
                    "${_ngi541_brew_openssl_root}"
                )

                find_package(
                    OpenSSL 3.0
                    QUIET
                    COMPONENTS Crypto
                )
            endif()
        endif()
    endif()

    if(NOT TARGET OpenSSL::Crypto)
        message(
            FATAL_ERROR
            "NGI541 differential tests require OpenSSL >= 3.0. "
            "Run scripts/bootstrap-differential-deps.sh to install the "
            "development dependency, or provide a compatible installation "
            "through the standard OPENSSL_ROOT_DIR CMake variable."
        )
    endif()

    if(DEFINED OPENSSL_VERSION)
        set(_ngi541_openssl_version "${OPENSSL_VERSION}")
    elseif(DEFINED OpenSSL_VERSION)
        set(_ngi541_openssl_version "${OpenSSL_VERSION}")
    else()
        set(_ngi541_openssl_version "unknown")
    endif()

    message(
        STATUS
        "NGI541 differential OpenSSL: "
        "${_ngi541_openssl_version}"
    )

    if(
        APPLE
        AND
        DEFINED _ngi541_brew_openssl_root
        AND
        NOT "${_ngi541_brew_openssl_root}" STREQUAL ""
    )
        message(
            STATUS
            "NGI541 differential OpenSSL root: "
            "${_ngi541_brew_openssl_root}"
        )
    endif()
endfunction()