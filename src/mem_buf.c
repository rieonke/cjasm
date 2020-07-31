//
// Created by Rieon Ke on 2020/7/23.
//

#include <string.h>
#include <stdlib.h>
#include "util.h"
#include "mem_buf.h"

cj_mem_buf_t *cj_mem_buf_new() {
    cj_mem_buf_t *buf = malloc(sizeof(cj_mem_buf_t));
    buf->data = NULL;
    buf->pos = 0;
    buf->length = 0;
    buf->positions = NULL;
    buf->positions_count = 0;
    return buf;
}

void cj_mem_buf_flush(cj_mem_buf_t *buf) {

    if (buf->data == NULL) {
        buf->data = malloc(sizeof(char) * buf->pos);
    } else {
        buf->data = realloc(buf->data, sizeof(char) * (buf->length + buf->pos));
    }

    for (int i = 0; i < buf->positions_count; ++i) {
        cj_mem_buf_pos_t *pos = buf->positions[i];
        if (pos == NULL) continue;
        if (pos->loc == 0) {
            pos->loc = 1;
            pos->pos += buf->length;
        }
    }

    memcpy(buf->data + buf->length, buf->buf, buf->pos);
    buf->length += buf->pos;
    buf->pos = 0;

}

void cj_mem_buf_check_full(cj_mem_buf_t *buf, u4 nlen) {
    if (buf->pos + nlen >= CJ_BUFFER_SIZE - 1) {
        cj_mem_buf_flush(buf);
    }
}


void cj_mem_buf_write_u1(cj_mem_buf_t *buf, u1 data) {
    cj_mem_buf_check_full(buf, 1);
    buf->buf[buf->pos++] = data;
}

void cj_mem_buf_write_u2(cj_mem_buf_t *buf, u2 data) {
    cj_mem_buf_check_full(buf, 2);
    cj_wu2(buf->buf + buf->pos, data);
    buf->pos += 2;
}

void cj_mem_buf_write_u4(cj_mem_buf_t *buf, u4 data) {
    cj_mem_buf_check_full(buf, 4);
    cj_wu4(buf->buf + buf->pos, data);
    buf->pos += 4;
}

void cj_mem_buf_write_u8(cj_mem_buf_t *buf, u8 data) {
    cj_mem_buf_check_full(buf, 8);
    cj_wu8(buf->buf + buf->pos, data);
    buf->pos += 8;
}

void cj_mem_buf_write_i1(cj_mem_buf_t *buf, i1 data) {
    cj_mem_buf_check_full(buf, 1);
    buf->buf[buf->pos++] = data;
}

void cj_mem_buf_write_i2(cj_mem_buf_t *buf, i2 data) {
    cj_mem_buf_check_full(buf, 2);
    cj_wi2(buf->buf + buf->pos, data);
    buf->pos += 2;
}

void cj_mem_buf_write_i4(cj_mem_buf_t *buf, i4 data) {
    cj_mem_buf_check_full(buf, 4);
    cj_wi4(buf->buf + buf->pos, data);
    buf->pos += 4;
}

void cj_mem_buf_write_i8(cj_mem_buf_t *buf, i8 data) {
    cj_mem_buf_check_full(buf, 8);
    cj_wi8(buf->buf + buf->pos, data);
    buf->pos += 8;
}

void cj_mem_buf_write_str(cj_mem_buf_t *buf, char *str, int len) {
    cj_mem_buf_check_full(buf, len);

    u2 w_len = 0;
    while (w_len < len) {
        u2 available = CJ_BUFFER_SIZE - buf->pos;
        u2 copy_len = len - w_len < available ? len - w_len : available;

        memcpy(buf->buf + buf->pos, str + w_len, copy_len);
        buf->pos += copy_len;
        w_len += copy_len;

        cj_mem_buf_check_full(buf, copy_len);
    }


}

void cj_mem_buf_write_buf(cj_mem_buf_t *buf, cj_mem_buf_t *buf1) {
    if (buf1 == NULL) return;
    cj_mem_buf_flush(buf1);
    cj_mem_buf_check_full(buf, buf1->length);

    u4 w_len = 0;
    u4 len = buf1->length;
    while (w_len < len) {
        u2 available = CJ_BUFFER_SIZE - buf->pos;
        u2 copy_len = len - w_len < available ? len - w_len : available;

        memcpy(buf->buf + buf->pos, buf1->data + w_len, copy_len);
        buf->pos += copy_len;
        w_len += copy_len;

        cj_mem_buf_check_full(buf, copy_len);
    }
}

void cj_mem_buf_free(cj_mem_buf_t *buf) {
    if (buf == NULL) return;
    for (int i = 0; i < buf->positions_count; ++i) {
        cj_mem_buf_pos_t *pos = buf->positions[i];
        cj_sfree(pos);
    }
    cj_sfree(buf->positions);
    cj_sfree(buf->data);
    cj_sfree(buf);
}

cj_mem_buf_pos_t *cj_mem_buf_pos(cj_mem_buf_t *buf) {
    if (buf == NULL) return NULL;
    cj_mem_buf_pos_t *pos = malloc(sizeof(cj_mem_buf_pos_t));
    pos->buf = buf;

    if (buf->data != NULL && buf->length > 0) {
        pos->loc = 1;
        pos->pos = buf->length;
    } else {
        pos->loc = 0;
        pos->pos = buf->pos > 0 ? buf->pos : 0;
    }

    if (buf->positions == NULL) {
        buf->positions = malloc(sizeof(cj_mem_buf_pos_t *) * ++buf->positions_count);
    } else {
        buf->positions = realloc(buf->positions, sizeof(cj_mem_buf_pos_t *) * ++buf->positions_count);
    }
    buf->positions[buf->positions_count - 1] = pos;

    return pos;
}

void cj_mem_buf_pos_wu4(cj_mem_buf_pos_t *pos, u4 data) {

    if (pos == NULL || pos->buf == NULL) return;
    cj_mem_buf_t *buf = pos->buf; //todo 目前仅支持在pos后，手动插入placeholder，不支持在末尾插入
    if (pos->loc == 0) {
        cj_wu4(buf->buf + pos->pos, data);
    } else {
        cj_wu4(buf->data + pos->pos, data);
    }
}

void cj_mem_buf_pos_wu2(cj_mem_buf_pos_t *pos, u2 data) {

    if (pos == NULL || pos->buf == NULL) return;
    cj_mem_buf_t *buf = pos->buf; //todo 目前仅支持在pos后，手动插入placeholder，不支持在末尾插入
    if (pos->loc == 0) {
        cj_wu2(buf->buf + pos->pos, data);
    } else {
        cj_wu2(buf->data + pos->pos, data);
    }
}
