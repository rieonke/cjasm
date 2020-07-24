//
// Created by Rieon Ke on 2020/7/23.
//

#ifndef CJASM_CLASS_H
#define CJASM_CLASS_H

#include <cjasm.h>
#include "annotation.h"

bool cj_class_add_annotation(cj_class_t *ctx, cj_annotation_t *ann, bool visible);

cj_field_t *cj_class_get_field_by_name(cj_class_t *ctx, const_str name);


CJ_INTERNAL void cj_class_update_name(cj_class_t *ctx, const_str name);

#endif //CJASM_CLASS_H
