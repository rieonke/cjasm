//
// Created by Rieon Ke on 2020/7/21.
//

#ifndef CJASM_CPOOL_H
#define CJASM_CPOOL_H

#include "util.h"
#include "mem_buf.h"

cj_cpool_t *cj_cp_parse(buf_ptr buf);

cj_mem_buf_t *cj_cp_to_buf2(cj_class_t *ctx);

void cj_cp_free(cj_cpool_t *cpool);

CJ_INTERNAL bool cj_cp_update_str(cj_class_t *ctx, const_str name, size_t len, u2 index);

CJ_INTERNAL bool cj_cp_update_class(cj_class_t *ctx, u2 idx, u2 name_idx);

#endif //CJASM_CPOOL_H
