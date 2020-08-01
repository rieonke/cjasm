//
// Created by Rieon Ke on 2020/7/22.
//

#ifndef CJASM_DESCRIPTOR_H
#define CJASM_DESCRIPTOR_H

#include "def.h"

struct cj_descriptor_s {
    bool is_field;
    bool is_method;
    int parameter_count;
    cj_type_t **parameter_types;
    cj_type_t *type;
};

struct cj_type_s {
    char *raw_name;
    char *raw_package;
    char *name;
    char *simple_name;
    char *package;
    bool is_array;
    bool is_primitive;
};


cj_type_t *cj_type_parse(char const *str);

void cj_type_free(cj_type_t *type);

bool cj_type_is_primitive(char const *str);

CJ_INTERNAL unsigned char *cj_descriptor_to_string(cj_descriptor_t *desc);

CJ_INTERNAL cj_descriptor_t *cj_descriptor_parse(const_str desc, size_t len);

CJ_INTERNAL void cj_descriptor_free(cj_descriptor_t *desc);

#endif //CJASM_DESCRIPTOR_H
