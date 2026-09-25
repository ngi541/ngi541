if(
    NOT DEFINED NGI541_ACVP_RUNNER
    OR NGI541_ACVP_RUNNER STREQUAL ""
)
    message(
        FATAL_ERROR
        "NGI541_ACVP_RUNNER is not defined or empty"
    )
endif()

if(NOT EXISTS "${NGI541_ACVP_RUNNER}")
    message(
        FATAL_ERROR
        "NGI541 ACVP runner does not exist: "
        "${NGI541_ACVP_RUNNER}"
    )
endif()

execute_process(
    COMMAND
        "${NGI541_ACVP_RUNNER}"
        --registration

    RESULT_VARIABLE runner_result
    OUTPUT_VARIABLE registration_json
    ERROR_VARIABLE runner_stderr

    OUTPUT_STRIP_TRAILING_WHITESPACE
)

if(NOT runner_result EQUAL 0)
    message(
        FATAL_ERROR
        "NGI541 ACVP registration generation failed (${runner_result})\n"
        "stderr:\n${runner_stderr}"
    )
endif()

#
# Registration must be a JSON array.
#
string(
    JSON registration_type
    TYPE "${registration_json}"
)

if(NOT registration_type STREQUAL "ARRAY")
    message(
        FATAL_ERROR
        "ACVP registration root is not an array"
    )
endif()

string(
    JSON registration_count
    LENGTH "${registration_json}"
)

if(NOT registration_count EQUAL 5)
    message(
        FATAL_ERROR
        "Expected exactly 5 ACVP capabilities, got "
        "${registration_count}"
    )
endif()

#
# Locate algorithms semantically rather than relying on array order.
#
unset(cbc_index)
unset(ctr_index)
unset(gcm_index)
unset(sha224_index)
unset(sha256_index)

math(
    EXPR registration_last
    "${registration_count} - 1"
)

foreach(index RANGE 0 ${registration_last})

    string(
        JSON algorithm
        GET "${registration_json}"
        ${index}
        algorithm
    )

    if(algorithm STREQUAL "ACVP-AES-CBC")

        if(DEFINED cbc_index)
            message(FATAL_ERROR "Duplicate ACVP-AES-CBC capability")
        endif()

        set(cbc_index ${index})

    elseif(algorithm STREQUAL "ACVP-AES-CTR")

        if(DEFINED ctr_index)
            message(FATAL_ERROR "Duplicate ACVP-AES-CTR capability")
        endif()

        set(ctr_index ${index})

    elseif(algorithm STREQUAL "ACVP-AES-GCM")

        if(DEFINED gcm_index)
            message(FATAL_ERROR "Duplicate ACVP-AES-GCM capability")
        endif()

        set(gcm_index ${index})

    elseif(algorithm STREQUAL "SHA2-224")

        if(DEFINED sha224_index)
            message(FATAL_ERROR "Duplicate SHA2-224 capability")
        endif()

        set(sha224_index ${index})

    elseif(algorithm STREQUAL "SHA2-256")

        if(DEFINED sha256_index)
            message(FATAL_ERROR "Duplicate SHA2-256 capability")
        endif()

        set(sha256_index ${index})

    else()

        message(
            FATAL_ERROR
            "Unexpected ACVP capability: ${algorithm}"
        )

    endif()

endforeach()

foreach(required_index
        cbc_index
        ctr_index
        gcm_index
        sha224_index
        sha256_index)

    if(NOT DEFINED ${required_index})
        message(
            FATAL_ERROR
            "Required ACVP capability missing: ${required_index}"
        )
    endif()

endforeach()

#
# Helper: exact numeric array.
#
function(assert_numeric_array object_index field)

    set(expected_values ${ARGN})

    string(
        JSON actual_length
        LENGTH "${registration_json}"
        ${object_index}
        ${field}
    )

    list(LENGTH expected_values expected_length)

    if(NOT actual_length EQUAL expected_length)
        message(
            FATAL_ERROR
            "${field}: expected ${expected_length} values, "
            "got ${actual_length}"
        )
    endif()

    math(EXPR last_index "${actual_length} - 1")

    foreach(i RANGE 0 ${last_index})

        string(
            JSON actual_value
            GET "${registration_json}"
            ${object_index}
            ${field}
            ${i}
        )

        list(GET expected_values ${i} expected_value)

        if(NOT actual_value EQUAL expected_value)
            message(
                FATAL_ERROR
                "${field}[${i}] mismatch: "
                "expected ${expected_value}, got ${actual_value}"
            )
        endif()

    endforeach()

endfunction()

#
# Helper: min/max/increment domain containing exactly one object.
#
function(assert_domain object_index field expected_min expected_max expected_increment)

    string(
        JSON domain_count
        LENGTH "${registration_json}"
        ${object_index}
        ${field}
    )

    if(NOT domain_count EQUAL 1)
        message(
            FATAL_ERROR
            "${field}: expected exactly one domain"
        )
    endif()

    string(
        JSON actual_min
        GET "${registration_json}"
        ${object_index}
        ${field}
        0
        min
    )

    string(
        JSON actual_max
        GET "${registration_json}"
        ${object_index}
        ${field}
        0
        max
    )

    string(
        JSON actual_increment
        GET "${registration_json}"
        ${object_index}
        ${field}
        0
        increment
    )

    if(NOT actual_min EQUAL expected_min)
        message(
            FATAL_ERROR
            "${field}.min mismatch: "
            "expected ${expected_min}, got ${actual_min}"
        )
    endif()

    if(NOT actual_max EQUAL expected_max)
        message(
            FATAL_ERROR
            "${field}.max mismatch: "
            "expected ${expected_max}, got ${actual_max}"
        )
    endif()

    if(NOT actual_increment EQUAL expected_increment)
        message(
            FATAL_ERROR
            "${field}.increment mismatch: "
            "expected ${expected_increment}, got ${actual_increment}"
        )
    endif()

endfunction()

#
# Helper: common AES direction/revision/keyLen checks.
#
function(assert_aes_common object_index)

    string(
        JSON revision
        GET "${registration_json}"
        ${object_index}
        revision
    )

    if(NOT revision STREQUAL "1.0")
        message(
            FATAL_ERROR
            "Unexpected AES revision: ${revision}"
        )
    endif()

    string(
        JSON direction_count
        LENGTH "${registration_json}"
        ${object_index}
        direction
    )

    if(NOT direction_count EQUAL 2)
        message(
            FATAL_ERROR
            "AES capability must advertise encrypt and decrypt"
        )
    endif()

    string(
        JSON direction_0
        GET "${registration_json}"
        ${object_index}
        direction
        0
    )

    string(
        JSON direction_1
        GET "${registration_json}"
        ${object_index}
        direction
        1
    )

    if(
        NOT (
            direction_0 STREQUAL "encrypt"
            AND direction_1 STREQUAL "decrypt"
        )
    )
        message(
            FATAL_ERROR
            "Unexpected AES directions: "
            "${direction_0}, ${direction_1}"
        )
    endif()

    assert_numeric_array(
        ${object_index}
        keyLen
        128
        192
        256
    )

endfunction()

#
# AES-CBC
#
assert_aes_common(${cbc_index})

#
# AES-CTR
#
assert_aes_common(${ctr_index})

string(
    JSON ctr_incremental
    GET "${registration_json}"
    ${ctr_index}
    incrementalCounter
)

if(NOT ctr_incremental)
    message(
        FATAL_ERROR
        "AES-CTR incrementalCounter must be true"
    )
endif()

string(
    JSON ctr_overflow
    GET "${registration_json}"
    ${ctr_index}
    overflowCounter
)

if(ctr_overflow)
    message(
        FATAL_ERROR
        "AES-CTR overflowCounter must be false"
    )
endif()

string(
    JSON ctr_tests
    GET "${registration_json}"
    ${ctr_index}
    performCounterTests
)

if(NOT ctr_tests)
    message(
        FATAL_ERROR
        "AES-CTR performCounterTests must be true"
    )
endif()

assert_domain(
    ${ctr_index}
    payloadLen
    8
    128
    8
)

#
# AES-GCM
#
assert_aes_common(${gcm_index})

string(
    JSON gcm_iv_gen
    GET "${registration_json}"
    ${gcm_index}
    ivGen
)

if(NOT gcm_iv_gen STREQUAL "external")
    message(
        FATAL_ERROR
        "AES-GCM ivGen must be external, got ${gcm_iv_gen}"
    )
endif()

string(
    JSON gcm_iv_gen_mode
    GET "${registration_json}"
    ${gcm_index}
    ivGenMode
)

if(NOT gcm_iv_gen_mode STREQUAL "8.2.1")
    message(
        FATAL_ERROR
        "AES-GCM ivGenMode must be 8.2.1, got "
        "${gcm_iv_gen_mode}"
    )
endif()

assert_numeric_array(
    ${gcm_index}
    tagLen
    128
)

assert_domain(
    ${gcm_index}
    ivLen
    96
    96
    8
)

assert_domain(
    ${gcm_index}
    payloadLen
    0
    65536
    8
)

assert_domain(
    ${gcm_index}
    aadLen
    0
    65536
    8
)

#
# SHA helper.
#
function(assert_sha object_index expected_algorithm)

    string(
        JSON algorithm
        GET "${registration_json}"
        ${object_index}
        algorithm
    )

    if(NOT algorithm STREQUAL expected_algorithm)
        message(
            FATAL_ERROR
            "Unexpected SHA algorithm: ${algorithm}"
        )
    endif()

    string(
        JSON revision
        GET "${registration_json}"
        ${object_index}
        revision
    )

    if(NOT revision STREQUAL "1.0")
        message(
            FATAL_ERROR
            "${expected_algorithm}: unexpected revision ${revision}"
        )
    endif()

    assert_domain(
        ${object_index}
        messageLength
        0
        65536
        8
    )

endfunction()

assert_sha(
    ${sha224_index}
    "SHA2-224"
)

assert_sha(
    ${sha256_index}
    "SHA2-256"
)

message(
    STATUS
    "NGI541 ACVP registration profile v1 semantic check passed"
)