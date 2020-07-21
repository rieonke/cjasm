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
    u2 *cp_offsets = malloc(cp_len * sizeof(u2)); //常量池偏移地址映射，根据常量下标[1,cp_len)获取，第0位元素弃用
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

    //cj_class_priv_t初始化
    privc(cls)->dirty = false;
    privc(cls)->cp_len = cp_len;
    privc(cls)->header = header;
    privc(cls)->cp_offsets = cp_offsets;
    privc(cls)->cp_cache = calloc(cp_len, sizeof(char *));
    privc(cls)->cp_types = cp_types;
    privc(cls)->this_class = this_class;
    privc(cls)->super_class = super_class;
    privc(cls)->buf = malloc(sizeof(char) * len);
    privc(cls)->buf_len = len;
    privc(cls)->cp_entries = NULL;
    privc(cls)->cp_entries_len = 0;
    privc(cls)->annotation_set = NULL;
    privc(cls)->annotation_set_initialized = false;
    memcpy((unsigned char *) privc(cls)->buf, buf, len);

    cj_parse_offset(cls);


    u2 offset = privc(cls)->cp_offsets[privc(cls)->this_class];
    u2 name_index = cj_ru2(privc(cls)->buf + offset);

    cls->raw_name = cj_cp_get_str(cls, name_index);

#define cj_str_replace(str, len, find, replace) \
    {                                           \
        for (int i = 0; i < len; ++i ) {        \
            if (str[i] == (char)find) {         \
                ((char*)str)[i] = replace;      \
            }                                   \
        }                                       \
    }

    cls->name = (const_str) strdup((char *) cls->raw_name);
    cj_str_replace(cls->name, strlen((char *) cls->name), '/', '.');
    char *short_name = strrchr((char *) cls->raw_name, '/');
    cls->short_name = short_name ? (const_str) short_name + 1 : cls->raw_name;
    int package_len = (int) (cls->short_name - cls->raw_name);
    cls->package = (const_str) strndup((char *) cls->name, package_len);
    cls->raw_package = (const_str) strdup((char *) cls->package);

    if (package_len > 0) {
        cj_str_replace(cls->raw_package, package_len, '.', '/');
    }

    return cls;
}

const_str cj_cp_get_str(cj_class_t *ctx, u2 idx) {

    if (idx >= privc(ctx)->cp_len && privc(ctx)->cp_entries == NULL) {
        return NULL;
    }

    //如果该索引在原有常量池范围内，则在原有的常量池中查找
    //否则如果索引已经超过了原有常量池的大小，则从新增常量数组中查找.

    if (privc(ctx)->cp_len > idx) {
        if (privc(ctx)->cp_cache[idx] == NULL) {
            u2 offset = privc(ctx)->cp_offsets[idx];
            const_str ptr = privc(ctx)->buf + offset;

            u2 len = cj_ru2(ptr);
            privc(ctx)->cp_cache[idx] = malloc(sizeof(char) * (len + 1));
            privc(ctx)->cp_cache[idx][len] = 0;
            memcpy(privc(ctx)->cp_cache[idx], ptr + 2, len);
        }
        return privc(ctx)->cp_cache[idx];
    }

    u2 new_idx = idx - privc(ctx)->cp_len;
    if (new_idx >= 0 && new_idx < privc(ctx)->cp_entries_len) {
        cj_cp_entry_t *entry = privc(ctx)->cp_entries[new_idx];
        if (entry == NULL) return NULL;
        if (entry->tag != CONSTANT_Utf8) return NULL;
        return entry->data;
    }

    return NULL;
}

void cj_class_free(cj_class_t *ctx) {
    if (ctx == NULL) return;
    cj_sfree((void *) privc(ctx)->buf);
    cj_sfree(privc(ctx)->cp_offsets);
    cj_sfree(privc(ctx)->cp_types);

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

    if (privc(ctx)->cp_entries != NULL) {
        for (int i = 0; i < privc(ctx)->cp_entries_len; ++i) {
            cj_cp_entry_t *entry = privc(ctx)->cp_entries[i];
            if (entry == NULL) continue;
            free(entry->data);
            free(entry);
        }
        free(privc(ctx)->cp_entries);
    }

    for (int i = 0; i < privc(ctx)->cp_len; ++i) {
        if (privc(ctx)->cp_cache[i] != NULL) {
            free(privc(ctx)->cp_cache[i]);
            privc(ctx)->cp_cache[i] = NULL;
        }
    }

    if (privc(ctx)->annotation_set != NULL) {
        cj_annotation_set_free(privc(ctx)->annotation_set);
    }
    cj_sfree((char *) ctx->name);
    cj_sfree((char *) ctx->package);
    cj_sfree((char *) ctx->raw_package);

    cj_sfree(privc(ctx)->cp_cache);
    cj_sfree(privc(ctx));
    cj_sfree(ctx);
}

bool cj_class_to_buf(cj_class_t *ctx, unsigned char **out, size_t *len) {
    if (!privc(ctx)->dirty) {

        *len = privc(ctx)->buf_len;
        *out = malloc(sizeof(unsigned char *) * *len);
        memcpy(*out, privc(ctx)->buf, *len);
        return true;
    }
    return false;
}

u2 cj_class_get_field_count(cj_class_t *ctx) {
    return ctx->field_count;
}

const_str cj_class_get_name(cj_class_t *ctx) {
    return ctx->name;
}

const_str cj_class_get_short_name(cj_class_t *ctx) {
    return ctx->short_name;
}

const_str cj_class_get_raw_name(cj_class_t *ctx) {
    return ctx->raw_name;
}

const_str cj_class_get_raw_package(cj_class_t *ctx) {
    return ctx->raw_package;
}

const_str cj_class_get_package(cj_class_t *ctx) {
    return ctx->package;
}


cj_field_t *cj_class_get_field(cj_class_t *ctx, u2 idx) {
    if (ctx->field_count <= 0 ||
        idx >= ctx->field_count ||
        privc(ctx) == NULL ||
        privc(ctx)->field_set == NULL) {
        return NULL;
    }

    return cj_field_set_get(ctx, privc(ctx)->field_set, idx);
}

const_str cj_field_get_name(cj_field_t *field) {
    return field->name;
}

u2 cj_field_get_access_flags(cj_field_t *field) {
    return field->access_flags;
}

const_str cj_field_get_descriptor(cj_field_t *field) {
    return field->descriptor;
}

u2 cj_field_get_attribute_count(cj_field_t *field) {
    return field->attribute_count;
}

cj_attribute_t *cj_field_get_attribute(cj_field_t *field, u2 idx) {
    if (field->klass == NULL ||
        field->attribute_count <= 0 ||
        privf(field)->attribute_set == NULL ||
        idx >= privf(field)->attribute_set->count) {
        return NULL;
    }
    return cj_attribute_set_get(field->klass, privf(field)->attribute_set, idx);
}

u2 cj_field_get_annotation_count(cj_field_t *field) {

    if (field == NULL ||
        privf(field) == NULL ||
        field->klass == NULL ||
        field->attribute_count <= 0) {
        return 0;
    }

    if (privf(field)->annotation_set == NULL && !privf(field)->annotation_set_initialized) {
        bool init = cj_annotation_set_init(field->klass, privf(field)->attribute_set, &privf(field)->annotation_set);
        privf(field)->annotation_set_initialized = init;
    }

    if (privf(field)->annotation_set == NULL) return 0;
    return privf(field)->annotation_set->count;
}

cj_annotation_t *cj_field_get_annotation(cj_field_t *field, u2 idx) {
    if (field == NULL ||
        privf(field) == NULL ||
        field->klass == NULL) {
        return NULL;
    }

    if (privf(field)->annotation_set == NULL && !privf(field)->annotation_set_initialized) {
        bool init = cj_annotation_set_init(field->klass, privf(field)->attribute_set, &privf(field)->annotation_set);
        privf(field)->annotation_set_initialized = init;
    }

    return cj_annotation_set_get(field->klass, privf(field)->annotation_set, idx);
}


void cj_field_set_name(cj_field_t *field, const_str name) {
    u2 idx = 0;
    const_str new_name = cj_cp_put_str(field->klass, name, strlen((char *) name), &idx);
    field->name = new_name;
}

u2 cj_class_get_method_count(cj_class_t *ctx) {
    return ctx->method_count;
}

cj_method_t *cj_class_get_method(cj_class_t *ctx, u2 idx) {
    if (ctx == NULL ||
        privc(ctx) == NULL ||
        idx >= ctx->method_count ||
        privc(ctx)->method_set == NULL) {
        return NULL;
    }

    return cj_method_set_get(ctx, privc(ctx)->method_set, idx);

}

const_str cj_method_get_name(cj_method_t *method) {
    return method->name;
}

u2 cj_method_get_access_flags(cj_method_t *method) {
    return method->access_flags;
}

u2 cj_class_get_attribute_count(cj_class_t *ctx) {
    return ctx->attr_count;
}

cj_attribute_t *cj_class_get_attribute(cj_class_t *ctx, u2 idx) {
    if (ctx == NULL ||
        privc(ctx) == NULL ||
        privc(ctx)->attribute_set == NULL ||
        idx >= privc(ctx)->attribute_set->count) {
        return NULL;
    }

    return cj_attribute_set_get(ctx, privc(ctx)->attribute_set, idx);
}

enum cj_attr_type cj_attr_parse_type(const_str type_str) {
#define comp_type(t) \
    if(strcmp((char*) type_str,#t) == 0) { \
        return   CJ_ATTR_##t;        \
    }

    comp_type(AnnotationDefault)
    comp_type(BootstrapMethods)
    comp_type(Code)
    comp_type(ConstantValue)
    comp_type(Deprecated)
    comp_type(EnclosingMethod)
    comp_type(Exceptions)
    comp_type(InnerClasses)
    comp_type(LineNumberTable)
    comp_type(LocalVariableTable)
    comp_type(LocalVariableTypeTable)
    comp_type(MethodParameters)
    comp_type(Module)
    comp_type(ModuleMainClass)
    comp_type(ModulePackages)
    comp_type(NestHost)
    comp_type(NestMembers)
    comp_type(RuntimeInvisibleAnnotations)
    comp_type(RuntimeInvisibleParameterAnnotations)
    comp_type(RuntimeInvisibleTypeAnnotations)
    comp_type(RuntimeVisibleAnnotations)
    comp_type(RuntimeVisibleParameterAnnotations)
    comp_type(RuntimeVisibleTypeAnnotations)
    comp_type(Signature)
    comp_type(SourceDebugExtension)
    comp_type(SourceFile)
    comp_type(StackMapTable)
    comp_type(Synthetic)

    return CJ_ATTR_NONE;

#undef comp_type
}

u2 cj_class_get_annotation_count(cj_class_t *ctx) {

    if (ctx == NULL || privc(ctx) == NULL || privc(ctx)->attribute_set == NULL) { return 0; }

    if (privc(ctx)->annotation_set == NULL && !privc(ctx)->annotation_set_initialized) {
        bool init = cj_annotation_set_init(ctx, privc(ctx)->attribute_set, &privc(ctx)->annotation_set);
        privc(ctx)->annotation_set_initialized = init;
    }

    if (privc(ctx)->annotation_set == NULL) return 0;
    return privc(ctx)->annotation_set->count;
}

cj_annotation_t *cj_class_get_annotation(cj_class_t *ctx, u2 idx) {

    if (ctx == NULL || privc(ctx) == NULL) return NULL;
    u2 attr_count = cj_class_get_attribute_count(ctx);
    if (idx >= attr_count) return NULL;

    if (privc(ctx)->annotation_set == NULL && !privc(ctx)->annotation_set_initialized) {
        bool init = cj_annotation_set_init(ctx, privc(ctx)->attribute_set, &privc(ctx)->annotation_set);
        privc(ctx)->annotation_set_initialized = init;
    }
    return cj_annotation_set_get(ctx, privc(ctx)->annotation_set, idx);
}

u4 cj_cp_get_u4(cj_class_t *ctx, u2 idx) {
    u2 offset = privc(ctx)->cp_offsets[idx];
    return cj_ru4(privc(ctx)->buf + offset);
}

u8 cj_cp_get_u8(cj_class_t *ctx, u2 idx) {
    u2 offset = privc(ctx)->cp_offsets[idx];
    return cj_ru8(privc(ctx)->buf + offset);
}

int cj_cp_get_int(cj_class_t *ctx, u2 idx) {
    u4 num_u4 = cj_cp_get_u4(ctx, idx);
    int number = num_u4;
    return number;
}

u2 cj_method_get_attribute_count(cj_method_t *method) {

    return method->attribute_count;
}

cj_attribute_t *cj_method_get_attribute(cj_method_t *method, u2 idx) {
    if (method->klass == NULL ||
        method->attribute_count <= 0 ||
        privm(method)->attribute_set == NULL ||
        privm(method)->attribute_set->count <= idx) {
        return NULL;
    }

    return cj_attribute_set_get(method->klass, privm(method)->attribute_set, idx);
}

u2 cj_method_get_annotation_count(cj_method_t *method) {

    if (method == NULL ||
        privm(method) == NULL ||
        method->klass == NULL ||
        method->attribute_count <= 0) {
        return 0;
    }

    if (privm(method)->annotation_set == NULL && !privm(method)->annotation_set_initialized) {
        bool init = cj_annotation_set_init(method->klass, privm(method)->attribute_set, &privm(method)->annotation_set);
        privm(method)->annotation_set_initialized = init;
    }

    if (privm(method)->annotation_set == NULL) return 0;
    return privm(method)->annotation_set->count;
}

cj_annotation_t *cj_method_get_annotation(cj_method_t *method, u2 idx) {
    if (method == NULL ||
        privm(method) == NULL ||
        method->klass == NULL) {
        return NULL;
    }

    if (privm(method)->annotation_set == NULL && !privm(method)->annotation_set_initialized) {
        bool init = cj_annotation_set_init(method->klass, privm(method)->attribute_set, &privm(method)->annotation_set);
        privm(method)->annotation_set_initialized = init;
    }

    return cj_annotation_set_get(method->klass, privm(method)->annotation_set, idx);
}

cj_code_t *cj_method_get_code(cj_method_t *method) {

    if (method == NULL ||
        method->klass == NULL ||
        privm(method) == NULL) {
        return NULL;
    }
    if (privm(method)->code != NULL) {
        return privm(method)->code;
    }

    /*
     *
     * Code_attribute {
     *      u2 attribute_name_index;
     *      u4 attribute_length;
     *      u2 max_stack;
     *      u2 max_locals;
     *      u4 code_length;
     *      u1 code[code_length];
     *      u2 exception_table_length;
     *      {   u2 start_pc;
     *          u2 end_pc;
     *          u2 handler_pc;
     *          u2 catch_type;
     *      } exception_table[exception_table_length];
     *      u2 attributes_count;
     *      attribute_info attributes[attributes_count];
     *  }
     *
     */
    u4 offset = 0;
    cj_class_t *ctx = method->klass;

    for (int i = 0; i < privm(method)->attribute_set->count; ++i) {
        cj_attribute_t *attr = cj_attribute_set_get(method->klass, privm(method)->attribute_set, i);
        if (attr->type == CJ_ATTR_Code) {
            offset = priva(attr)->offset;
        }
    }

    if (offset == 0) return NULL;
    u2 max_stack = cj_ru2(privc(ctx)->buf + offset + 6);
    u2 max_locals = cj_ru2(privc(ctx)->buf + offset + 8);
    u4 code_length = cj_ru4(privc(ctx)->buf + offset + 10);
    offset += 14;

    cj_code_t *code = malloc(sizeof(cj_code_t));
    code->offset = offset;
    code->length = code_length;
    code->max_stack = max_stack;
    code->max_locals = max_locals;
    code->method = method;

    privm(method)->code = code;

    return code;
}

cj_descriptor_t *cj_method_get_descriptor(cj_method_t *method) {
    if (method == NULL || method->descriptor == NULL || privm(method) == NULL) return NULL;
    if (privm(method)->descriptor == NULL) {
        privm(method)->descriptor = cj_descriptor_parse(method->descriptor, strlen((char *) method->descriptor));
    }
    return privm(method)->descriptor;
}

const_str cj_method_get_return_type(cj_method_t *method) {
    cj_descriptor_t *descriptor = cj_method_get_descriptor(method);
    return descriptor->type;
}

u2 cj_method_get_parameter_count(cj_method_t *method) {
    cj_descriptor_t *descriptor = cj_method_get_descriptor(method);
    return descriptor->parameter_count;
}


