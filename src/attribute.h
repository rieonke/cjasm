//
// Created by Rieon Ke on 2020/7/24.
//

#ifndef CJASM_ATTRIBUTE_H
#define CJASM_ATTRIBUTE_H

#include "util.h"

CJ_INTERNAL void cj_attribute_parse_offsets(buf_ptr ptr, u4 offset, u4 **offsets, u4 len);

CJ_INTERNAL cj_attribute_t *cj_attribute_group_get(cj_class_t *ctx, cj_attribute_group_t *set, u2 idx);

CJ_INTERNAL void cj_attribute_group_free(cj_attribute_group_t *set);

CJ_INTERNAL void cj_attribute_free(cj_attribute_t *attr);


#endif //CJASM_ATTRIBUTE_H
