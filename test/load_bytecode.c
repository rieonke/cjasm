//
// Created by Rieon Ke on 2020/7/9.
//
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "cjasm.h"
#include <setjmp.h>
#include <cmocka.h>


#define TEST_CLASS "Test.class"
#define MAJOR_VERSION 50
#define MINOR_VERSION 0
#define INIT_IDX 11

#define CTX ((cj_class_t*)*state)

static int setup(void **state) {

    unsigned char *buf = NULL;
    long len = cj_load_file(TEST_CLASS, &buf);
    assert(len > 0);
    assert_non_null(buf);

    *state = cj_class_new(buf, len);

    free(buf);

    assert_non_null(state);
    return 0;
}

static int teardown(void **state) {
    cj_class_free(CTX);
    return 0;
}

void test_check_version(void **state) {
    assert_int_equal(CTX->major_version, MAJOR_VERSION);
    assert_int_equal(CTX->minor_version, MINOR_VERSION);
}

void test_check_access_flags(void **state) {
    assert_int_equal(CTX->access_flags, 0x21);
}

void test_get_str(void **ctx) {

    char *str = cj_cp_get_str(*ctx, INIT_IDX);
    char *str1 = cj_cp_get_str(*ctx, INIT_IDX);

    assert_non_null(str);
    assert_string_equal(str, "<init>");

    assert_ptr_equal(str, str1);
    assert_non_null(str1);
    assert_string_equal(str1, "<init>");

}


int main(void) {

    const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_check_access_flags),
            cmocka_unit_test(test_check_version),
            cmocka_unit_test(test_get_str),
    };

    return cmocka_run_group_tests(tests, setup, teardown);
}