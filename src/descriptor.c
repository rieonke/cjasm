//
// Created by Rieon Ke on 2020/7/22.
//

#include "descriptor.h"

CJ_INTERNAL void cj_descriptor_free(cj_descriptor_t *desc) {
    for (int i = 0; i < desc->parameter_count; ++i) {
        cj_sfree(desc->parameter_types[i]);
    }
    cj_sfree(desc->parameter_types);
    cj_sfree(desc->type);
    cj_sfree(desc);
}

CJ_INTERNAL const char *cj_descriptor_parse_primitive(unsigned char c) {
    switch (c) {
        case 'B':
            return "byte";
        case 'C':
            return "char";
        case 'D':
            return "double";
        case 'F':
            return "float";
        case 'I':
            return "int";
        case 'J':
            return "long";
        case 'S':
            return "short";
        case 'Z':
            return "boolean";
        case 'V':
            return "void";
        default:
            return NULL;
    }

}

CJ_INTERNAL const char *cj_descriptor_type_to_str(unsigned char *type, int *olen, bool *need_free) {

    *need_free = false;
    *olen = 1;
    if (strcmp((char *) type, "byte") == 0) {
        return "B" ;
    }
    if (strcmp((char *) type, "char") == 0) {
        return "C" ;
    }
    if (strcmp((char *) type, "double") == 0) {
        return "D" ;
    }
    if (strcmp((char *) type, "float") == 0) {
        return "F" ;
    }
    if (strcmp((char *) type, "int") == 0) {
        return "I" ;
    }
    if (strcmp((char *) type, "long") == 0) {
        return "J" ;
    }
    if (strcmp((char *) type, "short") == 0) {
        return "S" ;
    }
    if (strcmp((char *) type, "boolean") == 0) {
        return "Z" ;
    }
    if (strcmp((char *) type, "void") == 0) {
        return "V" ;
    }

    size_t len = strlen((char *) type);
    *olen = len + 2;
    char *new_str = malloc(sizeof(char) * (len + 3));
    new_str[0] = 'L';
    memcpy(new_str + 1, type, len);
    new_str[len + 1] = ';';
    new_str[len + 2] = '\0';
    *need_free = true;

    return new_str;

}

CJ_INTERNAL cj_descriptor_t *cj_descriptor_parse(const_str desc, size_t len) {

    //fixme 支持数组的解析

    cj_descriptor_t *descriptor;
    bool in_type = false;
    bool in_arr = false;
    bool in_parameter = false;
    bool is_method = false;
    unsigned char type_buff[1024] = {0};
    int type_pos = 0;

    char *type = NULL;

    const char *types[256] = {0};
    int types_len = 0;

    for (int i = 0; i < len; ++i) {
        unsigned char c = desc[i];
        switch (c) {
            case '(':
                if (in_parameter) {
                    fprintf(stderr, "Error: invalid descriptor string, at pos %d\n", i);
                    return NULL;
                }
                in_parameter = true;
                is_method = true;
                break;
            case ')':
                if (!in_parameter) {
                    fprintf(stderr, "Error: invalid descriptor string, at pos %d\n", i);
                    return NULL;
                }
                in_parameter = false;
                break;
            case '[':
                in_arr = true;
                break;
            case ';':
                if (in_type) {
                    in_type = false;
                    if (in_parameter) {
                        types[types_len++] = strndup((char *) type_buff, type_pos);
                    } else {
                        type = strndup((char *) type_buff, type_pos);
                    }
                    type_pos = 0;
                }
                break;
            case 'L':
                if (!in_type) {
                    in_type = true;
                    break;
                }
            case 'B':
            case 'C':
            case 'D':
            case 'F':
            case 'I':
            case 'J':
            case 'S':
            case 'Z':
            case 'V':
                if (!in_type) {
                    const char *str = cj_descriptor_parse_primitive(c);
                    if (in_parameter) {
                        types[types_len++] = strdup(str);
                    } else {
                        type = strdup(str);
                    }
                    break;
                }
            default:
                if (in_type) {
                    type_buff[type_pos++] = c;
                }
                break;
        }
    }

    descriptor = malloc(sizeof(cj_descriptor_t));
    descriptor->type = (unsigned char *) type;
    descriptor->parameter_types = malloc(sizeof(char *) * types_len);
    memcpy(descriptor->parameter_types, types, sizeof(char *) * types_len);
    descriptor->parameter_count = types_len;
    descriptor->is_method = is_method;

    return descriptor;
}

unsigned char *cj_descriptor_to_string(cj_descriptor_t *desc) {

    unsigned char buf[2048] = {0};
    int buf_pos = 0;

#define DESC_METHOD_START buf[buf_pos++] = '(';

#define DESC_METHOD_END buf[buf_pos++] = ')';

    if (desc->is_method) {
        DESC_METHOD_START
        for (int i = 0; i < desc->parameter_count; ++i) {
            unsigned char *type = desc->parameter_types[i];
            bool need_free = false;
            int len = 0;
            const char *res = cj_descriptor_type_to_str(type, &len, &need_free);
            memcpy(buf + buf_pos, res, len);
            buf_pos += len;
            if (need_free) {
                free((char *) res);
            }
        }
        DESC_METHOD_END
    }

    bool need_free = false;
    int len = 0;
    const char *res = cj_descriptor_type_to_str(desc->type, &len, &need_free);
    memcpy(buf + buf_pos, res, len);
    buf_pos += len;


    unsigned char *out_str = malloc(sizeof(char) * buf_pos + 1);
    out_str[buf_pos] = 0;
    memcpy(out_str, buf, buf_pos);

    return out_str;
}





