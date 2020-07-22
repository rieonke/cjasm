//
// Created by Rieon Ke on 2020/7/22.
//

#ifndef CJASM_DESCRIPTOR_H
#define CJASM_DESCRIPTOR_H

#include "util.h"

CJ_INTERNAL unsigned char *cj_descriptor_to_string(cj_descriptor_t *desc);

CJ_INTERNAL cj_descriptor_t *cj_descriptor_parse(const_str desc, size_t len);

CJ_INTERNAL void cj_descriptor_free(cj_descriptor_t *desc);

#endif //CJASM_DESCRIPTOR_H
