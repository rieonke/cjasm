//
// Created by Rieon Ke on 2020/7/31.
//
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>
#include "../src/mem_buf.h"


void test_mem_buf(void **state) {
    cj_mem_buf_t *buf = cj_mem_buf_new();
    cj_mem_buf_printf(buf, "%s\n", "hello world");
    cj_mem_buf_write_u1(buf,0);
    cj_mem_buf_flush(buf);
    assert_string_equal("hello world\n", buf->data);
    cj_mem_buf_free(buf);
}


int main(void) {

    const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_mem_buf),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
