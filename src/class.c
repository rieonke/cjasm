//
// Created by Rieon Ke on 2020/7/21.
//

#include <cjasm.h>
#include <assert.h>
#include "util.h"
#include "cpool.h"
#include "descriptor.h"

#define CJ_CLASS_NAME_DIRTY 0x1


#define cj_str_replace(str, len, find, replace) \
    {                                           \
        for (int i = 0; i < len; ++i ) {        \
            if (str[i] == (char)find) {         \
                ((char*)str)[i] = replace;      \
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
        *out = malloc(sizeof(u1) * *len); //todo 覆盖所有未初始化的字节

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

unsigned char *cj_descriptor_replace_type(const_str descriptor, const_str old_element, const_str new_element) {
    cj_descriptor_t *desc = cj_descriptor_parse(descriptor, strlen((char *) descriptor));
    for (int i = 0; i < desc->parameter_count; ++i) {
        //todo replace
    }

    //todo replace type

    return cj_descriptor_to_string(desc);
}

void cj_class_set_name(cj_class_t *ctx, unsigned char *name) {
    if (ctx == NULL || privm(ctx) == NULL) return;

    if (strcmp((char *) ctx->name, (char *) name) == 0) {
        return;
    }

    //convert
    const_str old_name = ctx->raw_name;
    unsigned char *t_name = (unsigned char *) strdup((char *) name);
    cj_str_replace(t_name, strlen((char *) t_name), '.', '/')

    u2 index = 0;
    const_str new_name = cj_cp_put_str(ctx, t_name, strlen((char *) t_name), &index);
    privc(ctx)->dirty |= CJ_CLASS_NAME_DIRTY;
    cj_cp_update_class(ctx, privc(ctx)->this_class, index);

    //find all descriptor
    cj_cpool_t *cpool = privc(ctx)->cpool;
    for (int i = 0; i < cpool->descriptors_len; ++i) {
        u2 idx = cpool->descriptors[i];
        const_str descriptor = cj_cp_get_str(ctx, idx);

        unsigned char *new_desc = cj_descriptor_replace_type(descriptor, old_name, new_name);
        printf("%s\n", new_desc); //todo impl this
    }


    cj_class_update_name(ctx, new_name);

    free(t_name);
}

CJ_INTERNAL void cj_class_update_name(cj_class_t *ctx, const_str raw) {

    if (privc(ctx)->initialized) {
        cj_sfree((char *) ctx->name);
        cj_sfree((char *) ctx->package);
        cj_sfree((char *) ctx->raw_package);
    }

    ctx->raw_name = raw;

    ctx->name = (const_str) strdup((char *) ctx->raw_name);
    cj_str_replace(ctx->name, strlen((char *) ctx->name), '/', '.');
    char *short_name = strrchr((char *) ctx->raw_name, '/');
    ctx->short_name = short_name ? (const_str) short_name + 1 : ctx->raw_name;
    int package_len = (int) (ctx->short_name - ctx->raw_name) - 1;
    ctx->package = (const_str) strndup((char *) ctx->name, package_len);
    ctx->raw_package = (const_str) strdup((char *) ctx->package);

    if (package_len > 0) {
        cj_str_replace(ctx->raw_package, package_len, '.', '/');
    }

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

    cj_cpool_t *cpool = cj_cp_parse(buf);

    //头部偏移量，为最后一个常量后一位，
    // 类access_flags，方法、字段等从此偏移量以后可查
    u4 header = cpool->tail_offset;

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

    //cj_class_priv_t初始化
    privc(cls)->initialized = false;
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

    privc(cls)->initialized = true;

    return cls;
}

void cj_class_free(cj_class_t *ctx) {
    if (ctx == NULL) return;
    cj_sfree((void *) privc(ctx)->buf);
    cj_sfree(privc(ctx)->cpool->offsets);
    cj_sfree(privc(ctx)->cpool->types);

    cj_method_set_free(privc(ctx)->method_set);
    cj_field_set_free(privc(ctx)->field_set);

    cj_attribute_set_free(privc(ctx)->attribute_set);
    if (privc(ctx)->method_attribute_sets != NULL) {
        for (int i = 0; i < ctx->method_count; ++i) {
            cj_attribute_set_free(privc(ctx)->method_attribute_sets[i]);
        }
        cj_sfree(privc(ctx)->method_attribute_sets);
    }

    if (privc(ctx)->field_attribute_sets != NULL) {

        for (int i = 0; i < ctx->field_count; ++i) {
            cj_attribute_set_free(privc(ctx)->field_attribute_sets[i]);
        }
        cj_sfree(privc(ctx)->field_attribute_sets);
    }

    cj_cp_free(privc(ctx)->cpool);

    if (privc(ctx)->annotation_set != NULL) {
        cj_annotation_set_free(privc(ctx)->annotation_set);
    }
    cj_sfree((char *) ctx->name);
    cj_sfree((char *) ctx->package);
    cj_sfree((char *) ctx->raw_package);

    cj_sfree(privc(ctx));
    cj_sfree(ctx);
}

