add_subdirectory(support)
add_subdirectory(core)

if(NGI541_BUILD_ENGINE)
    add_subdirectory(engine)
endif()