//
// Created by Rieon Ke on 2020/7/21.
//

#ifndef CJASM_CPOOL_H
#define CJASM_CPOOL_H

#include "util.h"
#include "mem_buf.h"

cj_cpool_t *cj_cp_parse(buf_ptr buf);

u4 cj_cp_get_tail_offset(cj_cpool_t *ctx);

cj_mem_buf_t *cj_cp_to_buf2(cj_class_t *ctx);

void cj_cp_free(cj_cpool_t *cpool);

CJ_INTERNAL bool cj_cp_update_str(cj_class_t *ctx, const_str name, size_t len, u2 index);

CJ_INTERNAL bool cj_cp_update_class(cj_class_t *ctx, u2 idx, u2 name_idx);

CJ_INTERNAL const_str cj_cp_put_str(cj_class_t *ctx, const_str name, size_t len, u2 *index);

CJ_INTERNAL void cj_cp_add_descriptor_idx(cj_cpool_t *cpool, u2 desc_idx);

CJ_INTERNAL u2 cj_cp_get_descriptor_idx(cj_cpool_t *cpool, u2 idx);

CJ_INTERNAL u2 cj_cp_get_descriptor_count(cj_cpool_t *cpool);

CJ_INTERNAL u2 cj_cp_get_class_idx(cj_cpool_t *cpool, u2 idx);

CJ_INTERNAL u2 cj_cp_get_class_count(cj_cpool_t *cpool);

CJ_INTERNAL u2 cj_cp_get_u2(cj_class_t *ctx, u2 idx);

CJ_INTERNAL u2 cj_cp_get_length(cj_cpool_t *cpool);

CJ_INTERNAL u2 cj_cp_get_str_index(cj_class_t *ctx, const_str str);

#endif //CJASM_CPOOL_H
