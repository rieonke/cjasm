cmake_minimum_required(VERSION 3.16)
project(cjasm C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DCJ_DEBUG")

include(third_party/ThirdParty.cmake)

include_directories(include)

add_library(cjasm-object OBJECT include/cjasm.h src/cjasm.c src/util.h)
add_library(cjasm-shared SHARED $<TARGET_OBJECTS:cjasm-object>)
add_library(cjasm-static STATIC $<TARGET_OBJECTS:cjasm-object>)

set_target_properties(cjasm-object PROPERTIES POSITION_INDEPENDENT_CODE 1)
set_target_properties(cjasm-static PROPERTIES OUTPUT_NAME cjasm)
set_target_properties(cjasm-shared PROPERTIES OUTPUT_NAME cjasm)

function(cjasm_add_ctest name)
    add_executable(test_${name} test/${name}.c)
    target_link_libraries(test_${name} cjasm-static cmocka)
    add_dependencies(test_${name} cjasm-static libcmocka)
    add_test(NAME test_${name} COMMAND test_${name})
endfunction()

file(GLOB TEST_FILES "test/resources/*")
foreach (tf IN LISTS TEST_FILES)
    configure_file(${tf} ${CMAKE_BINARY_DIR} COPYONLY)
    message(STATUS "copy test resource ${tf}")
endforeach ()

enable_testing()
cjasm_add_ctest(load_bytecode)

