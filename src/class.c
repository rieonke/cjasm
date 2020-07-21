//
// Created by Rieon Ke on 2020/7/21.
//

#include <cjasm.h>
#include <assert.h>
#include "util.h"
#include "cpool.h"

#define CJ_CLASS_NAME_DIRTY 0x1


#define cj_str_replace(str, len, find, replace) \
    {                                           \
        for (int i = 0; i < len; ++i ) {        \
            if (str[i] == (char)find) {               \
                ((char*)str)[i] = replace;               \
            }                                   \
        }                                       \
    }

/**
 * 设置class、field、method、attribute的偏移量offset
 * @param ctx java类
 * @return 设置是否成功
 */
CJ_INTERNAL bool cj_parse_offset(cj_class_t *ctx) {

    const_str ptr = privc(ctx)->buf;
    u4 offset = privc(ctx)->header + 6;

    u4 methods_count;
    u2 interfaces_count;
    u2 fields_count;
    u2 attributes_count;

    cj_field_set_t *field_set = NULL;
    cj_method_set_t *method_set = NULL;

    cj_attribute_set_t *class_attribute_set = NULL;
    cj_attribute_set_t **field_attribute_sets = NULL;
    cj_attribute_set_t **method_attribute_sets = NULL;

    interfaces_count = cj_ru2(ptr + offset);
    offset += 2 + interfaces_count * 2;

    fields_count = cj_ru2(ptr + offset);
    offset += 2;

    if (fields_count > 0) {
        field_set = malloc(sizeof(cj_field_set_t));
        field_set->index = 0;
        field_set->count = fields_count;
        field_set->cache = NULL;
        field_set->offsets = malloc(sizeof(u4) * fields_count);

        field_attribute_sets = malloc(sizeof(cj_attribute_set_t *) * fields_count);

        for (int i = 0; i < fields_count; ++i) {
            field_set->offsets[i] = offset;

            cj_attribute_set_t *attribute_set = NULL;

            u4 attributes_length = cj_ru2(ptr + offset + 6);
            offset += 8;

            if (attributes_length > 0) {

                attribute_set = malloc(sizeof(cj_attribute_set_t));

                attribute_set->index = i;
                attribute_set->count = attributes_length;
                attribute_set->offsets = malloc(sizeof(u4) * attributes_length);
                attribute_set->cache = NULL;

                for (int j = 0; j < attributes_length; ++j) {
                    attribute_set->offsets[j] = offset;
                    u4 attribute_length = cj_ru4(ptr + offset + 2);
                    offset += attribute_length + 6;
                }
            }

            field_attribute_sets[i] = attribute_set;
        }
    }

    methods_count = cj_ru2(ptr + offset);
    offset += 2;

    if (methods_count > 0) {
        method_set = malloc(sizeof(cj_method_set_t));
        method_set->index = 0;
        method_set->count = methods_count;
        method_set->cache = NULL;
        method_set->offsets = malloc(sizeof(u4) * methods_count);


        method_attribute_sets = malloc(sizeof(cj_attribute_set_t *) * methods_count);

        for (int i = 0; i < methods_count; ++i) {
            method_set->offsets[i] = offset;

            cj_attribute_set_t *attribute_set = NULL;

            u4 attributes_length = cj_ru2(ptr + offset + 6);
            offset += 8;

            if (attributes_length > 0) {

                attribute_set = malloc(sizeof(cj_attribute_set_t));
                attribute_set->index = i;
                attribute_set->count = attributes_length;
                attribute_set->offsets = malloc(sizeof(u4) * attributes_length);
                attribute_set->cache = NULL;


                for (int j = 0; j < attributes_length; ++j) {
                    attribute_set->offsets[j] = offset;

                    u4 attribute_length = cj_ru4(ptr + offset + 2);
                    offset += attribute_length + 6;
                }
            }

            method_attribute_sets[i] = attribute_set;
        }
    }

    attributes_count = cj_ru2(ptr + offset);
    offset += 2;

    class_attribute_set = malloc(sizeof(cj_attribute_set_t));
    class_attribute_set->index = 0;
    class_attribute_set->count = attributes_count;
    class_attribute_set->cache = NULL;
    class_attribute_set->offsets = NULL;

    if (attributes_count > 0) {
        class_attribute_set->offsets = malloc(sizeof(u4) * attributes_count);
        for (int i = 0; i < attributes_count; ++i) {
            class_attribute_set->offsets[i] = offset;

            u4 attribute_length = cj_ru4(ptr + offset + 2);
            offset += attribute_length + 6;
        }
    }


    ctx->field_count = fields_count;
    ctx->method_count = methods_count;
    ctx->interface_count = interfaces_count;
    ctx->attr_count = attributes_count;

    privc(ctx)->field_set = field_set;
    privc(ctx)->method_set = method_set;
    privc(ctx)->attribute_set = class_attribute_set;

    privc(ctx)->field_attribute_sets = field_attribute_sets;
    privc(ctx)->method_attribute_sets = method_attribute_sets;

    return true;
}


bool cj_class_to_buf(cj_class_t *ctx, unsigned char **out, size_t *len) {
    if (privc(ctx)->dirty == 0) {
        *len = privc(ctx)->buf_len;
        *out = malloc(sizeof(unsigned char) * *len);
        memcpy(*out, privc(ctx)->buf, *len);
        return true;
    } else {
        cj_buf_t *buf = cj_cp_to_buf(ctx);
        assert(buf != NULL);

        u4 offset = 8 + buf->length;
        u4 body_len = privc(ctx)->buf_len - privc(ctx)->header;

        *len = body_len + buf->length + 8;
        *out = malloc(sizeof(u1) * *len);

        cj_wu4(*out, 0xCAFEBABE);
        cj_wu2(*out + 4, 0);
        cj_wu2(*out + 8, 52);

        memcpy(*out + 8, buf->buf, buf->length);
        memcpy(*out + offset, privc(ctx)->buf + privc(ctx)->header, body_len);

        free(buf->buf);
        free(buf);
    }
    return false;
}

void cj_class_set_name(cj_class_t *ctx, unsigned char *name) {
    if (ctx == NULL || privm(ctx) == NULL) return;

    if (strcmp((char *) ctx->name, (char *) name) == 0) {
        return;
    }

    //convert
    unsigned char *t_name = (unsigned char *) strdup((char *) name);
    cj_str_replace(t_name, strlen((char *) t_name), '.', '/')

    u2 index = 0;
    const_str new_name = cj_cp_put_str(ctx, t_name, strlen((char *) t_name), &index);
    privc(ctx)->dirty |= CJ_CLASS_NAME_DIRTY;
    privc(ctx)->this_class = index;

    cj_class_update_name(ctx, new_name);

    free(t_name);
}

CJ_INTERNAL void cj_class_update_name(cj_class_t *ctx, const_str raw) {

    ctx->raw_name = raw;

    ctx->name = (const_str) strdup((char *) ctx->raw_name);
    cj_str_replace(ctx->name, strlen((char *) ctx->name), '/', '.');
    ctx->short_name = (const_str) strrchr((char *) ctx->raw_name, '/') + 1;
}

cj_class_t *cj_class_new(unsigned char *buf, size_t len) {
    //如果buf为空或者buf的长度len小于一个字节码文件所占的最小大小，
    //字节码文件最小大小为ClassFile结构中所必须元素长度之和
    //比如 magic + version + cp count + 必要的cp entries + access + this_class 等
    //则返回NULL
    if (buf == NULL || len < 16) { //fixme 仔细算算
        fprintf(stderr, "ERROR: not a valid class bytecode buffer, to small\n");
        return NULL;
    }

    //根据magic判断是否为java的class字节码文件
    u4 magic = cj_ru4(buf);
    if (magic != 0xCAFEBABE) {
        fprintf(stderr, "ERROR: not a valid class bytecode buffer, invalid magic number\n");
        return NULL;
    }

    //分别读取java大小版本号
    u2 minor_v = cj_ru2(buf + 4);
    u2 major_v = cj_ru2(buf + 6);
    //常量池的个数
    u2 cp_len = cj_ru2(buf + 8);

    //todo check version

    //分配内存
    u4 *cp_offsets = malloc(cp_len * sizeof(u4)); //常量池偏移地址映射，根据常量下标[1,cp_len)获取，第0位元素弃用
    u1 *cp_types = malloc(cp_len * sizeof(u1));
    int cur_cp_idx = 1;
    u4 cur_cp_offset = 10;
    while (cur_cp_idx < cp_len) {

        int cp_size;
        enum cj_cp_type type = (enum cj_cp_type) cj_ru1(buf + cur_cp_offset++);

        *(cp_types + cur_cp_idx) = type;
        *(cp_offsets + cur_cp_idx) = cur_cp_offset;
        cur_cp_idx++;
        //判断常量池中每个常量的类型
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
                break;
            }
            default:
                fprintf(stderr, "ERROR: invalid class format, unrecognized cp entry tag: %d\n", type);
                free(cp_offsets);
                return NULL;
        }
        //设置当前常量的截止位置
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

    //cj_class_s初始化
    cls->major_version = major_v;
    cls->minor_version = minor_v;
    cls->access_flags = access_flags;
    cls->interface_count = interfaces_count;
    cls->priv = priv;

    cj_cpool_t *cpool = malloc(sizeof(cj_cpool_t));
    cpool->length = cp_len;
    cpool->types = cp_types;
    cpool->cache = calloc(cp_len, sizeof(unsigned char *));
    cpool->offsets = cp_offsets;
    cpool->entries = NULL;
    cpool->entries_len = 0;

    //cj_class_priv_t初始化
    privc(cls)->dirty = 0;
    privc(cls)->header = header;
    privc(cls)->this_class = this_class;
    privc(cls)->super_class = super_class;
    privc(cls)->buf = malloc(sizeof(char) * len);
    privc(cls)->buf_len = len;
    privc(cls)->cpool = cpool;
    privc(cls)->annotation_set = NULL;
    privc(cls)->annotation_set_initialized = false;
    memcpy((unsigned char *) privc(cls)->buf, buf, len);

    cj_parse_offset(cls);


    u2 offset = privc(cls)->cpool->offsets[privc(cls)->this_class];
    u2 name_index = cj_ru2(privc(cls)->buf + offset);

    const_str raw = cj_cp_get_str(cls, name_index);
    cj_class_update_name(cls, raw);

    return cls;
}

