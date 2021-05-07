//
// Created by Rieon Ke on 2020/7/22.
//

#include "descriptor.h"
#include "util.h"

CJ_INTERNAL void cj_descriptor_free(cj_descriptor_t *desc) {
    for (int i = 0; i < desc->parameter_count; ++i) {
        cj_type_free(desc->parameter_types[i]);
    }
    cj_sfree(desc->parameter_types);
    cj_type_free(desc->type);
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
    if (cj_streq(type, "byte")) {
        return "B";
    }
    if (cj_streq(type, "char")) {
        return "C";
    }
    if (cj_streq(type, "double")) {
        return "D";
    }
    if (cj_streq(type, "float")) {
        return "F";
    }
    if (cj_streq(type, "int")) {
        return "I";
    }
    if (cj_streq(type, "long")) {
        return "J";
    }
    if (cj_streq(type, "short")) {
        return "S";
    }
    if (cj_streq(type, "boolean")) {
        return "Z";
    }
    if (cj_streq(type, "void")) {
        return "V";
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

    char *types[256] = {0};
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

    if (in_arr)
        cj_debug("in arr: true\n");

    descriptor = malloc(sizeof(cj_descriptor_t));
    descriptor->type = cj_type_parse(type);
    free(type);

    if (types_len > 0) {
        descriptor->parameter_types = malloc(sizeof(char *) * types_len);
        for (int i = 0; i < types_len; ++i) {
            descriptor->parameter_types[i] = cj_type_parse(types[i]);
            free(types[i]);
        }
    } else {
        descriptor->parameter_types = NULL;
    }

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
            cj_type_t *type = desc->parameter_types[i];
            bool need_free = false;
            int len = 0;
            const char *res = cj_descriptor_type_to_str((unsigned char *) type->raw_name, &len, &need_free);
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
    const char *res = cj_descriptor_type_to_str((unsigned char *) desc->type->raw_name, &len, &need_free);
    memcpy(buf + buf_pos, res, len);
    buf_pos += len;
    cj_sfree((char *) res);


    unsigned char *out_str = malloc(sizeof(char) * buf_pos + 1);
    out_str[buf_pos] = 0;
    memcpy(out_str, buf, buf_pos);

    return out_str;
}

cj_type_t *cj_type_parse(const char *str) {

    cj_type_t *type = malloc(sizeof(cj_type_t));
    int package_len = 0;

    type->is_array = false;
    type->is_primitive = false;
    type->package = NULL;
    type->raw_package = NULL;
    type->simple_name = NULL;
    type->raw_name = strdup(str);
    type->name = strdup(type->raw_name);

    cj_str_replace(type->name, strlen(type->name), '/', '.');

    char *short_name = strrchr(type->raw_name, '/');
    type->simple_name = short_name ? short_name + 1 : type->raw_name;
    if (type->simple_name != type->raw_name) {
        package_len = (int) (type->simple_name - type->raw_name) - 1;
        type->package = strndup(type->name, package_len);
        type->raw_package = strdup(type->package);
    }

    if (package_len > 0) {
        cj_str_replace(type->raw_package, package_len, '.', '/');
    }
    type->is_primitive = cj_type_is_primitive(str);

    return type;
}

void cj_type_free(cj_type_t *type) {
    if (type == NULL) return;
    cj_sfree(type->raw_name);
    cj_sfree(type->name);
    cj_sfree(type->package);
    cj_sfree(type->raw_package);
    cj_sfree(type);
}

bool cj_type_is_primitive(const char *str) {
    if (strlen(str) > 7)return false;

    if (cj_streq("int", str)) {
        return true;
    }
    if (cj_streq("byte", str)) {
        return true;
    }
    if (cj_streq("char", str)) {
        return true;
    }
    if (cj_streq("long", str)) {
        return true;
    }
    if (cj_streq("void", str)) {
        return true;
    }
    if (cj_streq("short", str)) {
        return true;
    }
    if (cj_streq("float", str)) {
        return true;
    }
    if (cj_streq("double", str)) {
        return true;
    }
    if (cj_streq("boolean", str)) {
        return true;
    }
    return false;
}

