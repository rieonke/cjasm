//
// Created by Rieon Ke on 2020/7/23.
//

#ifndef CJASM_MEM_BUF_H
#define CJASM_MEM_BUF_H

#include "def.h"

#ifndef CJ_BUFFER_SIZE
#define CJ_BUFFER_SIZE 1024
#endif

struct cj_mem_buf_pos_s {
    u4 pos;
    u1 loc;
    cj_mem_buf_t *buf;
};

struct cj_mem_buf_s {
    u1 *data;
    u1 buf[CJ_BUFFER_SIZE];
    u4 pos;
    u4 length;
    cj_mem_buf_pos_t **positions;
    u2 positions_count;
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

cj_mem_buf_pos_t *cj_mem_buf_pos(cj_mem_buf_t *buf);

void cj_mem_buf_pos_wu4(cj_mem_buf_pos_t *pos, u4 data);

void cj_mem_buf_pos_wu2(cj_mem_buf_pos_t *pos, u2 data);

u4 cj_mem_buf_get_size(cj_mem_buf_t *buf);

void cj_mem_buf_back(cj_mem_buf_t *buf, u4 count);


#define cj_mem_buf_printf(buf, ...)                                            \
    {                                                                          \
        size_t __cj_mem_buf_p_size = snprintf(NULL,0, __VA_ARGS__) + 1;        \
        char * __cj_mem_buf_p_b = malloc(__cj_mem_buf_p_size);                 \
        snprintf(__cj_mem_buf_p_b, __cj_mem_buf_p_size, __VA_ARGS__);          \
        cj_mem_buf_write_str(buf, __cj_mem_buf_p_b, strlen(__cj_mem_buf_p_b)); \
        free(__cj_mem_buf_p_b);                                                \
    }


#endif //CJASM_MEM_BUF_H
