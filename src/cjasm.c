//
// Created by Rieon Ke on 2020/7/9.
//

#include "cjasm.h"
#include "./util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CJ_INTERNAL
#define priv(c) ((cj_class_priv_t*)(c->priv))
#define cj_sfree(ptr) if(ptr != NULL) free(ptr);

typedef struct cj_class_priv_s cj_class_priv_t;
struct cj_class_priv_s {
    unsigned char const *buf;

    u4 header;

    u2 cp_len;
    u2 *cp_offsets;
    char **cp_cache;

    u2 this_class;
    u2 super_class;

    cj_field_t **field_cache;
    u2 *field_offsets;

    u2 *method_offsets;
    u4 attribute_offset;
};

/*
 ClassFile {
    u4             magic;
    u2             minor_version;
    u2             major_version;
    u2             constant_pool_count;
    cp_info        constant_pool[constant_pool_count-1];
    u2             access_flags;
    u2             this_class;
    u2             super_class;
    u2             interfaces_count;
    u2             interfaces[interfaces_count];
    u2             fields_count;
    field_info     fields[fields_count];
    u2             methods_count;
    method_info    methods[methods_count];
    u2             attributes_count;
    attribute_info attributes[attributes_count];
}
 */



CJ_INTERNAL bool cj_parse_offset(cj_class_t *ctx) {

    const unsigned char *ptr = priv(ctx)->buf;
    u4 offset = priv(ctx)->header + 6;

    u4 methods_length = 0;
    u2 interfaces_count = 0;
    u2 fields_length = 0;
    u2 attributes_length = 0;
    u2 *field_offsets = NULL;
    u2 *method_offsets = NULL;

    interfaces_count = cj_ru2(ptr + offset);
    offset += 2 + interfaces_count * 2;

    fields_length = cj_ru2(ptr + offset);
    offset += 2;

    if (fields_length > 0) {
        field_offsets = malloc(sizeof(u2) * fields_length);
        for (int i = 0; i < fields_length; ++i) {
            field_offsets[i] = offset;
            attributes_length = cj_ru2(ptr + offset + 6);
            offset += 8;
            for (int j = 0; j < attributes_length; ++j) {
                u4 attribute_length = cj_ru4(ptr + offset + 2);
                offset += attribute_length + 6;
            }
        }
    }

    methods_length = cj_ru2(ptr + offset);
    offset += 2;

    if (methods_length > 0) {
        method_offsets = malloc(sizeof(u2) * methods_length);
        for (int i = 0; i < methods_length; ++i) {
            method_offsets[i] = offset;

            attributes_length = cj_ru2(ptr + offset + 6);
            offset += 8;
            for (int j = 0; j < attributes_length; ++j) {
                u4 attribute_length = cj_ru4(ptr + offset + 2);
                offset += attribute_length + 6;
            }
        }
    }

    ctx->interfaces_count = interfaces_count;
    ctx->field_count = fields_length;
    ctx->method_count = methods_length;
    ctx->interfaces_count = interfaces_count;
    priv(ctx)->field_offsets = field_offsets;
    priv(ctx)->method_offsets = method_offsets;
    priv(ctx)->attribute_offset = offset;

    return true;
}


long cj_load_file(char *path, unsigned char **buf) {

    FILE *f = NULL;
    long len;

    f = fopen(path, "r");
    if (!f) {
        return -1;
    }

    fseek(f, 0, SEEK_END);
    len = ftell(f);
    fseek(f, 0, SEEK_SET);

    *buf = malloc(sizeof(char) * (len + 1));
    (*buf)[len] = 0;

    fread(*buf, sizeof(char), len, f);
    fclose(f);

    return len;
}

cj_class_t *cj_class_new(unsigned char *buf, size_t len) {
    //如果buf为空或者buf的长度len小于一个字节码文件所占的最小大小，
    //字节码文件最小大小为ClassFile结构中所必须元素长度只和
    //比如 magic + version + cp count + 必要的cp entries + access + this_class 等
    //则返回NULL
    if (buf == NULL || len < 16) { //fixme 仔细算算
        fprintf(stderr, "ERROR: not a valid class bytecode buffer, to small\n");
        return NULL;
    }

    u4 magic = cj_ru4(buf);
    if (magic != 0xCAFEBABE) {
        fprintf(stderr, "ERROR: not a valid class bytecode buffer, invalid magic number\n");
        return NULL;
    }

    u2 minor_v = cj_ru2(buf + 4);
    u2 major_v = cj_ru2(buf + 6);
    u2 cp_len = cj_ru2(buf + 8);

    //todo check version

    u2 *cp_offsets = malloc(cp_len * sizeof(u2)); //常量池偏移地址映射，根据常量下标[1,cp_len)获取，第0位元素弃用
    int cur_cp_idx = 1;
    u4 cur_cp_offset = 10;
    while (cur_cp_idx < cp_len) {
        *(cp_offsets + cur_cp_idx++) = cur_cp_offset + 1;
        int cp_size = 0;

        //此处cur_cp_offset ++ 以后，
        //当前偏移量直接指向tag之后的数据区域
        //可以直接通过当前偏移量获取数据
        enum cj_cp_type type = (enum cj_cp_type) cj_ru1(buf + cur_cp_offset++);
#ifdef CJ_DEBUG
        printf("%d => ", cur_cp_idx - 1);
        print_type(type);
#endif
        switch (type) {
            /*+-----------------------------+-----+--------+
              |        Constant Kind        | Tag | Length |
              +-----------------------------+-----+--------+
              | CONSTANT_Class              |   7 | 2      |
              | CONSTANT_Fieldref           |   9 | 4      |
              | CONSTANT_Methodref          |  10 | 4      |
              | CONSTANT_InterfaceMethodref |  11 | 4      |
              | CONSTANT_String             |   8 | 2      |
              | CONSTANT_Integer            |   3 | 4      |
              | CONSTANT_Float              |   4 | 4      |
              | CONSTANT_Long               |   5 | 8      |
              | CONSTANT_Double             |   6 | 8      |
              | CONSTANT_NameAndType        |  12 | 4      |
              | CONSTANT_Utf8               |   1 | 2+     |
              | CONSTANT_MethodHandle       |  15 | 3      |
              | CONSTANT_MethodType         |  16 | 2      |
              | CONSTANT_Dynamic            |  17 | 4      |
              | CONSTANT_InvokeDynamic      |  18 | 4      |
              | CONSTANT_Module             |  19 | 2      |
              | CONSTANT_Package            |  20 | 2      |
              +-----------------------------+-----+--------+ */
            case CONSTANT_Class:
            case CONSTANT_String:
                //2
                cp_size = 2;
                break;
            case CONSTANT_Fieldref:
            case CONSTANT_Methodref:
            case CONSTANT_InterfaceMethodref:
                cp_size = 4;
                //4
                break;
            case CONSTANT_Float:
            case CONSTANT_Integer:
                cp_size = 4;
                //4
                break;
            case CONSTANT_Long:
            case CONSTANT_Double:
                cp_size = 8;
                cur_cp_idx++;
                //8
                break;
            case CONSTANT_NameAndType:
                cp_size = 4;
                //4
                break;
            case CONSTANT_MethodHandle:
                cp_size = 3;
                //3
                break;
            case CONSTANT_MethodType:
                cp_size = 2;
                //2
                break;
            case CONSTANT_Dynamic:
            case CONSTANT_InvokeDynamic:
                cp_size = 4;
                //4
                break;
            case CONSTANT_Module:
            case CONSTANT_Package:
                cp_size = 2;
                //2
                break;
            case CONSTANT_Utf8: {
                cp_size = 2 + cj_ru2(buf + cur_cp_offset);
#if CJ_DEBUG
                unsigned char *ptr = buf + cur_cp_offset + 2;
                char *str = calloc(sizeof(char *), cp_size);
                memcpy(str, ptr, cp_size - 2);
                printf(" %s", str);
                free(str);
#endif
                break;
            }
            default:
                fprintf(stderr, "ERROR: invalid class format, unrecognized cp entry tag: %d\n", type);
                free(cp_offsets);
                return NULL;
        }
#if CJ_DEBUG
        printf("\n");
#endif
        cur_cp_offset += cp_size;
    }

    //头部偏移量，为最后一个常量后一位，
    // 类access_flags，方法、字段等从此偏移量以后可查
    u4 header = cur_cp_offset;

    u2 access_flags = cj_ru2(buf + header);
    u2 this_class = cj_ru2(buf + header + 2);
    u2 super_class = cj_ru2(buf + header + 4);
    u2 interfaces_count = cj_ru2(buf + header + 6);


    cj_class_t *cls = malloc(sizeof(cj_class_t));
    cj_class_priv_t *priv = malloc(sizeof(cj_class_priv_t));

    cls->major_version = major_v;
    cls->minor_version = minor_v;
    cls->access_flags = access_flags;
    cls->interfaces_count = interfaces_count;
    cls->priv = priv;

    priv(cls)->cp_len = cp_len;
    priv(cls)->header = header;
    priv(cls)->cp_offsets = cp_offsets;
    priv(cls)->cp_cache = calloc(cp_len, sizeof(char *));
    priv(cls)->this_class = this_class;
    priv(cls)->super_class = super_class;
    priv(cls)->field_offsets = NULL;
    priv(cls)->method_offsets = NULL;
    priv(cls)->field_cache = NULL;
    priv(cls)->buf = malloc(sizeof(char) * len);
    memcpy((unsigned char *) priv(cls)->buf, buf, len);

    cj_parse_offset(cls);

    return cls;
}

char *cj_cp_get_str(cj_class_t *ctx, u2 idx) {

    if (priv(ctx)->cp_len - 1 < idx) {
        return NULL;
    }

    if (priv(ctx)->cp_cache[idx] == NULL) {
        u2 offset = priv(ctx)->cp_offsets[idx];
        const unsigned char *ptr = priv(ctx)->buf + offset;

        u2 len = cj_ru2(ptr);
        priv(ctx)->cp_cache[idx] = malloc(sizeof(char) * (len + 1));
        priv(ctx)->cp_cache[idx][len] = 0;
        memcpy(priv(ctx)->cp_cache[idx], ptr + 2, len);
    }

    return priv(ctx)->cp_cache[idx];
}

void cj_class_free(cj_class_t *ctx) {
    if (ctx == NULL) return;
    free((void *) priv(ctx)->buf);
    free(priv(ctx)->cp_offsets);

    if (priv(ctx)->method_offsets != NULL) {
        free(priv(ctx)->method_offsets);
    }

    if (priv(ctx)->field_offsets != NULL) {
        free(priv(ctx)->field_offsets);
    }

    if (priv(ctx)->field_cache != NULL) {
        for (int i = 0; i < ctx->field_count; ++i) {
            cj_sfree(priv(ctx)->field_cache[i]);
        }
        free(priv(ctx)->field_cache);
    }

    for (int i = 0; i < priv(ctx)->cp_len; ++i) {
        if (priv(ctx)->cp_cache[i] != NULL) {
            free(priv(ctx)->cp_cache[i]);
            priv(ctx)->cp_cache[i] = NULL;
        }
    }

    free(priv(ctx)->cp_cache);
    free(priv(ctx));
    free(ctx);
}


u2 cj_class_get_field_count(cj_class_t *ctx) {
    return ctx->field_count;
}

const char *cj_class_get_name(cj_class_t *ctx) {
    u2 offset = priv(ctx)->cp_offsets[priv(ctx)->this_class];
    u2 name_index = cj_ru2(priv(ctx)->buf + offset);
    return cj_cp_get_str(ctx, name_index);
}


cj_field_t *cj_class_get_field(cj_class_t *ctx, u2 idx) {
    if (ctx->field_count <= 0 || idx >= ctx->field_count) {
        return NULL;
    }

    if (priv(ctx)->field_cache == NULL) {
        //初始化字段缓存
        priv(ctx)->field_cache = calloc(sizeof(cj_field_t *), ctx->field_count);
        for (int i = 0; i < ctx->field_count; ++i) {
            priv(ctx)->field_cache[i] = NULL;
        }
    }

    if (priv(ctx)->field_cache[idx] == NULL) {

        u2 offset = priv(ctx)->field_offsets[idx];
        u2 access_flags = cj_ru2(priv(ctx)->buf + offset);
        u2 name_index = cj_ru2(priv(ctx)->buf + offset + 2);
        u2 descriptor_index = cj_ru2(priv(ctx)->buf + offset + 4);
        u2 attributes_count = cj_ru2(priv(ctx)->buf + offset + 6);

        cj_field_t *field = malloc(sizeof(cj_field_t));
        field->access_flags = access_flags;
        field->index = idx;
        field->klass = ctx;
        field->name = cj_cp_get_str(ctx, name_index);
        field->descriptor = cj_cp_get_str(ctx, descriptor_index);

        priv(ctx)->field_cache[idx] = field;
    }

    return priv(ctx)->field_cache[idx];
}

const char *cj_field_get_name(cj_field_t *field) {
    return field->name;
}

u2 cj_field_get_access_flags(cj_field_t *field) {
    return field->access_flags;
}

const char *cj_field_get_descriptor(cj_field_t *field) {
    return field->descriptor;
}
