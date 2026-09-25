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
        "AES-GCM completeness request does not exist: "
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
        "AES-GCM completeness runner failed (${runner_result})\n"
        "stdout:\n${runner_stdout}\n"
        "stderr:\n${runner_stderr}"
    )
endif()

if(NOT EXISTS "${NGI541_ACVP_RESPONSE}")
    message(
        FATAL_ERROR
        "AES-GCM completeness response was not created"
    )
endif()

file(
    READ
    "${NGI541_ACVP_RESPONSE}"
    response_json
)


#
# Vector-set identity.
#
string(
    JSON response_vs_id
    GET "${response_json}"
    1
    vsId
)

if(NOT response_vs_id EQUAL 9006)
    message(
        FATAL_ERROR
        "Unexpected AES-GCM completeness vsId: "
        "${response_vs_id}"
    )
endif()


#
# We intentionally keep one group for each independent
# parameter combination.
#
string(
    JSON group_count
    LENGTH "${response_json}"
    1
    testGroups
)

if(NOT group_count EQUAL 10)
    message(
        FATAL_ERROR
        "Expected 10 AES-GCM completeness groups, got "
        "${group_count}"
    )
endif()


function(assert_group group_index expected_tg_id expected_test_count)

    string(
        JSON actual_tg_id
        GET "${response_json}"
        1
        testGroups
        ${group_index}
        tgId
    )

    if(NOT actual_tg_id EQUAL expected_tg_id)
        message(
            FATAL_ERROR
            "Unexpected tgId at group ${group_index}: "
            "${actual_tg_id}"
        )
    endif()

    string(
        JSON actual_test_count
        LENGTH "${response_json}"
        1
        testGroups
        ${group_index}
        tests
    )

    if(NOT actual_test_count EQUAL expected_test_count)
        message(
            FATAL_ERROR
            "Unexpected test count for tgId=${expected_tg_id}: "
            "${actual_test_count}"
        )
    endif()

endfunction()


assert_group(0 101 1)
assert_group(1 102 1)
assert_group(2 103 1)
assert_group(3 104 2)
assert_group(4 105 1)
assert_group(5 106 1)
assert_group(6 107 1)
assert_group(7 108 1)
assert_group(8 109 1)
assert_group(9 110 1)


function(assert_hex expected)

    set(path ${ARGN})

    string(
        JSON actual
        GET "${response_json}"
        ${path}
    )

    string(TOUPPER "${actual}" actual_upper)
    string(TOUPPER "${expected}" expected_upper)

    if(NOT actual_upper STREQUAL expected_upper)
        message(
            FATAL_ERROR
            "AES-GCM value mismatch\n"
            "path:     ${path}\n"
            "expected: ${expected_upper}\n"
            "actual:   ${actual_upper}"
        )
    endif()

endfunction()


function(assert_tc_id group_index test_index expected_tc_id)

    string(
        JSON actual_tc_id
        GET "${response_json}"
        1
        testGroups
        ${group_index}
        tests
        ${test_index}
        tcId
    )

    if(NOT actual_tc_id EQUAL expected_tc_id)
        message(
            FATAL_ERROR
            "Unexpected tcId in group index ${group_index}: "
            "${actual_tc_id}"
        )
    endif()

endfunction()


#
# AES-192
#
assert_tc_id(0 0 1001)

assert_hex(
    "36562516078DC5FFE88FD5875CD127E296FC2B823F381117AFA330ABB76A3D99"
    1 testGroups 0 tests 0 ct
)

assert_hex(
    "D3DFD8BFA07D83A8772BA2F59C05BBEA"
    1 testGroups 0 tests 0 tag
)


assert_tc_id(1 0 1002)

string(
    JSON passed_1002
    GET "${response_json}"
    1 testGroups 1 tests 0 testPassed
)

if(NOT passed_1002)
    message(
        FATAL_ERROR
        "AES-192 valid decrypt tcId=1002 failed"
    )
endif()

assert_hex(
    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
    1 testGroups 1 tests 0 pt
)


#
# AES-256
#
assert_tc_id(2 0 1003)

assert_hex(
    "F21B845348BD3C29325568E5ED35DAD6E078DEAFB3B555D954CF562975B76036"
    1 testGroups 2 tests 0 ct
)

assert_hex(
    "E21DC38CF0FEB78935E9BA5AF6ECA920"
    1 testGroups 2 tests 0 tag
)


assert_tc_id(3 0 1004)

string(
    JSON passed_1004
    GET "${response_json}"
    1 testGroups 3 tests 0 testPassed
)

if(NOT passed_1004)
    message(
        FATAL_ERROR
        "AES-256 valid decrypt tcId=1004 failed"
    )
endif()

assert_hex(
    "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
    1 testGroups 3 tests 0 pt
)


#
# AES-256 bad tag.
#
assert_tc_id(3 1 1005)

string(
    JSON passed_1005
    GET "${response_json}"
    1 testGroups 3 tests 1 testPassed
)

if(passed_1005)
    message(
        FATAL_ERROR
        "AES-256 invalid tag tcId=1005 was accepted"
    )
endif()


#
# AES-128, zero AAD.
#
assert_tc_id(4 0 1006)

assert_hex(
    "DB5C0BA906F54CABF8F5A1C69CA28CF6"
    1 testGroups 4 tests 0 ct
)

assert_hex(
    "6566B0622233F0F9B74C3FB922EC34CC"
    1 testGroups 4 tests 0 tag
)


assert_tc_id(5 0 1007)

string(
    JSON passed_1007
    GET "${response_json}"
    1 testGroups 5 tests 0 testPassed
)

if(NOT passed_1007)
    message(
        FATAL_ERROR
        "Zero-AAD decrypt tcId=1007 failed"
    )
endif()

assert_hex(
    "404142434445464748494A4B4C4D4E4F"
    1 testGroups 5 tests 0 pt
)


#
# AES-128, zero payload + non-zero AAD.
#
# This is the regression case for the missing encrypt-side
# GHASH length-block finalization.
#
assert_tc_id(6 0 1008)

assert_hex(
    ""
    1 testGroups 6 tests 0 ct
)

assert_hex(
    "4659F8B330A6AC0F6E458F86E786ACEF"
    1 testGroups 6 tests 0 tag
)


assert_tc_id(7 0 1009)

string(
    JSON passed_1009
    GET "${response_json}"
    1 testGroups 7 tests 0 testPassed
)

if(NOT passed_1009)
    message(
        FATAL_ERROR
        "Zero-payload decrypt tcId=1009 failed"
    )
endif()

assert_hex(
    ""
    1 testGroups 7 tests 0 pt
)


#
# AES-128, zero payload + zero AAD.
#
assert_tc_id(8 0 1010)

assert_hex(
    ""
    1 testGroups 8 tests 0 ct
)

assert_hex(
    "B2E349391E251DE9C5E8989140FA411C"
    1 testGroups 8 tests 0 tag
)


assert_tc_id(9 0 1011)

string(
    JSON passed_1011
    GET "${response_json}"
    1 testGroups 9 tests 0 testPassed
)

if(NOT passed_1011)
    message(
        FATAL_ERROR
        "Zero-payload/zero-AAD decrypt tcId=1011 failed"
    )
endif()

assert_hex(
    ""
    1 testGroups 9 tests 0 pt
)


message(
    STATUS
    "AES-GCM completeness offline verification passed"
)