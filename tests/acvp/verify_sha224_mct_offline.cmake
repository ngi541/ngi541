if(
    NOT DEFINED NGI541_ACVP_RUNNER
    OR NGI541_ACVP_RUNNER STREQUAL ""
)
    message(
        FATAL_ERROR
        "NGI541_ACVP_RUNNER is not defined or empty"
    )
endif()

if(
    NOT DEFINED NGI541_ACVP_REQUEST
    OR NGI541_ACVP_REQUEST STREQUAL ""
)
    message(
        FATAL_ERROR
        "NGI541_ACVP_REQUEST is not defined or empty"
    )
endif()

if(
    NOT DEFINED NGI541_ACVP_RESPONSE
    OR NGI541_ACVP_RESPONSE STREQUAL ""
)
    message(
        FATAL_ERROR
        "NGI541_ACVP_RESPONSE is not defined or empty"
    )
endif()

if(NOT EXISTS "${NGI541_ACVP_RUNNER}")
    message(
        FATAL_ERROR
        "NGI541 ACVP runner does not exist: "
        "${NGI541_ACVP_RUNNER}"
    )
endif()

if(NOT EXISTS "${NGI541_ACVP_REQUEST}")
    message(
        FATAL_ERROR
        "SHA2-224 MCT request does not exist: "
        "${NGI541_ACVP_REQUEST}"
    )
endif()

file(REMOVE "${NGI541_ACVP_RESPONSE}")

execute_process(
    COMMAND
        "${NGI541_ACVP_RUNNER}"
        "${NGI541_ACVP_REQUEST}"
        "${NGI541_ACVP_RESPONSE}"

    RESULT_VARIABLE runner_result
    OUTPUT_VARIABLE runner_stdout
    ERROR_VARIABLE runner_stderr
)

if(NOT runner_result EQUAL 0)
    message(
        FATAL_ERROR
        "SHA2-224 MCT offline runner failed (${runner_result})\n"
        "stdout:\n${runner_stdout}\n"
        "stderr:\n${runner_stderr}"
    )
endif()

if(NOT EXISTS "${NGI541_ACVP_RESPONSE}")
    message(
        FATAL_ERROR
        "SHA2-224 MCT response file was not created"
    )
endif()

file(
    READ
    "${NGI541_ACVP_RESPONSE}"
    response_json
)

string(
    JSON response_vs_id
    GET "${response_json}"
    1
    vsId
)

if(NOT response_vs_id EQUAL 9005)
    message(
        FATAL_ERROR
        "Unexpected SHA2-224 MCT vsId: ${response_vs_id}"
    )
endif()

string(
    JSON group_count
    LENGTH "${response_json}"
    1
    testGroups
)

if(NOT group_count EQUAL 1)
    message(
        FATAL_ERROR
        "Expected exactly one SHA2-224 MCT group, got "
        "${group_count}"
    )
endif()

string(
    JSON tc_id
    GET "${response_json}"
    1
    testGroups
    0
    tests
    0
    tcId
)

if(NOT tc_id EQUAL 224001)
    message(
        FATAL_ERROR
        "Unexpected SHA2-224 MCT tcId: ${tc_id}"
    )
endif()

string(
    JSON result_count
    LENGTH "${response_json}"
    1
    testGroups
    0
    tests
    0
    resultsArray
)

if(NOT result_count EQUAL 100)
    message(
        FATAL_ERROR
        "Expected 100 SHA2-224 MCT results, got "
        "${result_count}"
    )
endif()


function(assert_md result_index expected)

    string(
        JSON actual
        GET "${response_json}"
        1
        testGroups
        0
        tests
        0
        resultsArray
        ${result_index}
        md
    )

    string(TOUPPER "${actual}" actual)
    string(TOUPPER "${expected}" expected_upper)

    if(NOT actual STREQUAL expected_upper)
        message(
            FATAL_ERROR
            "SHA2-224 MCT mismatch at outer=${result_index}\n"
            "expected: ${expected_upper}\n"
            "actual:   ${actual}"
        )
    endif()

endfunction()


assert_md(
    0
    "6C0D1C05AA94B8975D887F6ECEBF51EE57B3DF1F6FD13586E312419D"
)

assert_md(
    49
    "80D378414FEA0A6BD3DEE6EBA7114F73DB008DAD5DE302BFA2521169"
)

assert_md(
    99
    "EA26B2485EFCE7AF3176205DEF46988AC5CC97BBCF8D38189F2D7225"
)

message(
    STATUS
    "SHA2-224 ACVP MCT offline verification passed"
)