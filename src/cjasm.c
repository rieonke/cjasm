//
// Created by Rieon Ke on 2020/7/9.
//

#include "cjasm.h"
#include "./util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


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
            case CONSTANT_Utf8:
                cp_size = 2 + cj_ru2(buf + cur_cp_offset);
                break;
            default:
                fprintf(stderr, "ERROR: invalid class format, unrecognized cp entry tag: %d\n", type);
                free(cp_offsets);
                return NULL;
        }
        cur_cp_offset += cp_size;
    }

    //头部偏移量，为最后一个常量后一位，
    // 类access_flags，方法、字段等从此偏移量以后可查
    u4 header = cur_cp_offset;

    u2 access_flags = cj_ru2(buf + header);

    cj_class_t *cls = malloc(sizeof(cj_class_t));
    cls->buf = malloc(sizeof(char) * len);
    memcpy((unsigned char *) cls->buf, buf, len);
    cls->major_version = major_v;
    cls->minor_version = minor_v;
    cls->cp_len = cp_len;
    cls->header = header;
    cls->access_flags = access_flags;
    cls->cp_offsets = cp_offsets;
    cls->cp_cache = calloc(cp_len, sizeof(char *));
    return cls;
}

char *cj_cp_get_str(cj_class_t *ctx, u2 idx) {

    if (ctx->cp_len - 1 < idx) {
        return NULL;
    }

    if (ctx->cp_cache[idx] == NULL) {
        u2 offset = ctx->cp_offsets[idx];
        const unsigned char *ptr = ctx->buf + offset;

        u2 len = cj_ru2(ptr);
        ctx->cp_cache[idx] = malloc(sizeof(char) * (len + 1));
        ctx->cp_cache[idx][len] = 0;
        memcpy(ctx->cp_cache[idx], ptr + 2, len);
    }

    return ctx->cp_cache[idx];
}

void cj_class_free(cj_class_t *ctx) {
    if (ctx == NULL) return;
    free((void *) ctx->buf);
    free(ctx->cp_offsets);

    for (int i = 0; i < ctx->cp_len; ++i) {
        if (ctx->cp_cache[i] != NULL) {
            free(ctx->cp_cache[i]);
            ctx->cp_cache[i] = NULL;
        }
    }

    free(ctx->cp_cache);
    free(ctx);
}

