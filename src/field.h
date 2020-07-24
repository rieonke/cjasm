//
// Created by Rieon Ke on 2020/7/23.
//

#ifndef CJASM_FIELD_H
#define CJASM_FIELD_H

#include <cjasm.h>
#include "mem_buf.h"
#include "util.h"
#include "hashmap.h"

cj_field_group_t *cj_field_group_new(u2 count, u4 *offsets);

cj_field_t *cj_field_group_get_by_name(cj_class_t *ctx, cj_field_group_t *set, const_str name);

cj_field_t *cj_field_group_get(cj_class_t *ctx, cj_field_group_t *set, u2 idx);

cj_mem_buf_t *cj_field_to_buf(cj_field_t *field);

void cj_field_set_free(cj_field_group_t *set);

CJ_INTERNAL void cj_field_free(cj_field_t *field);


#endif //CJASM_FIELD_H
