//
// Created by Rieon Ke on 2020/7/23.
//

#ifndef CJASM_MEM_BUF_H
#define CJASM_MEM_BUF_H

#include "def.h"

#ifndef CJ_BUFFER_SIZE
#define CJ_BUFFER_SIZE 1024
#endif

typedef struct cj_mem_buf_s cj_mem_buf_t;

struct cj_mem_buf_s {
    u1 *data;
    u1 buf[CJ_BUFFER_SIZE];
    u4 pos;
    u4 length;
};


cj_mem_buf_t *cj_mem_buf_new();

void cj_mem_buf_flush(cj_mem_buf_t *buf);

void cj_mem_buf_check_full(cj_mem_buf_t *buf, u4 nlen);

void cj_mem_buf_write_u1(cj_mem_buf_t *buf, u1 data);

void cj_mem_buf_write_u2(cj_mem_buf_t *buf, u2 data);

void cj_mem_buf_write_u4(cj_mem_buf_t *buf, u4 data);

void cj_mem_buf_write_u8(cj_mem_buf_t *buf, u8 data);

void cj_mem_buf_write_i1(cj_mem_buf_t *buf, i1 data);

void cj_mem_buf_write_i2(cj_mem_buf_t *buf, i2 data);

void cj_mem_buf_write_i4(cj_mem_buf_t *buf, i4 data);

void cj_mem_buf_write_i8(cj_mem_buf_t *buf, i8 data);

void cj_mem_buf_write_str(cj_mem_buf_t *buf, char *str, int len);

void cj_mem_buf_write_buf(cj_mem_buf_t *buf, cj_mem_buf_t *buf1);

void cj_mem_buf_free(cj_mem_buf_t *buf);


#endif //CJASM_MEM_BUF_H
