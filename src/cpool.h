//
// Created by Rieon Ke on 2020/7/21.
//

#ifndef CJASM_CPOOL_H
#define CJASM_CPOOL_H

#include "util.h"

cj_cpool_t *cj_cp_parse(buf_ptr buf);

cj_buf_t *cj_cp_to_buf(cj_class_t *ctx);

void cj_cp_free(cj_cpool_t *cpool);


#endif //CJASM_CPOOL_H
