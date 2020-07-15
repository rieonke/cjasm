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



CJ_INTERNAL bool cj_parse_offset(cj_class_t *ctx) {

    const_str ptr = privc(ctx)->buf;
    u4 offset = privc(ctx)->header + 6;

    u4 methods_count;
    u2 interfaces_count;
    u2 fields_count;
    u2 attributes_count;
    u4 *field_offsets = NULL;
    u4 *method_offsets = NULL;
    u4 *attr_offsets = NULL;

    interfaces_count = cj_ru2(ptr + offset);
    offset += 2 + interfaces_count * 2;

    fields_count = cj_ru2(ptr + offset);
    offset += 2;

    if (fields_count > 0) {
        field_offsets = malloc(sizeof(u4) * fields_count);
        for (int i = 0; i < fields_count; ++i) {
            field_offsets[i] = offset;
            u4 attributes_length = cj_ru2(ptr + offset + 6);
            offset += 8;
            for (int j = 0; j < attributes_length; ++j) {
                u4 attribute_length = cj_ru4(ptr + offset + 2);
                offset += attribute_length + 6;
            }
        }
    }

    methods_count = cj_ru2(ptr + offset);
    offset += 2;

    if (methods_count > 0) {
        method_offsets = malloc(sizeof(u4) * methods_count);
        for (int i = 0; i < methods_count; ++i) {
            method_offsets[i] = offset;

            u4 attributes_length = cj_ru2(ptr + offset + 6);
            offset += 8;
            for (int j = 0; j < attributes_length; ++j) {
                u4 attribute_length = cj_ru4(ptr + offset + 2);
                offset += attribute_length + 6;
            }
        }
    }

    attributes_count = cj_ru2(ptr + offset);
    offset += 2;
    if (attributes_count > 0) {
        attr_offsets = malloc(sizeof(u4) * attributes_count);
        for (int i = 0; i < attributes_count; ++i) {
            attr_offsets[i] = offset;

            u4 attribute_length = cj_ru4(ptr + offset + 2);
            offset += attribute_length + 6;
        }
    }


    ctx->field_count = fields_count;
    ctx->method_count = methods_count;
    ctx->interface_count = interfaces_count;
    ctx->attr_count = attributes_count;
    privc(ctx)->field_offsets = field_offsets;
    privc(ctx)->method_offsets = method_offsets;
    privc(ctx)->attr_offsets = attr_offsets;

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
    u1 *cp_types = malloc(cp_len * sizeof(u1));
    int cur_cp_idx = 1;
    u4 cur_cp_offset = 10;
    while (cur_cp_idx < cp_len) {

        int cp_size;
        enum cj_cp_type type = (enum cj_cp_type) cj_ru1(buf + cur_cp_offset++);

        *(cp_types + cur_cp_idx) = type;
        *(cp_offsets + cur_cp_idx) = cur_cp_offset;
        cur_cp_idx++;
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
    cls->interface_count = interfaces_count;
    cls->priv = priv;

    privc(cls)->dirty = false;
    privc(cls)->cp_len = cp_len;
    privc(cls)->header = header;
    privc(cls)->cp_offsets = cp_offsets;
    privc(cls)->cp_cache = calloc(cp_len, sizeof(char *));
    privc(cls)->cp_types = cp_types;
    privc(cls)->this_class = this_class;
    privc(cls)->super_class = super_class;
    privc(cls)->field_offsets = NULL;
    privc(cls)->field_cache = NULL;
    privc(cls)->method_offsets = NULL;
    privc(cls)->method_cache = NULL;
    privc(cls)->attr_offsets = NULL;
    privc(cls)->attr_cache = NULL;
    privc(cls)->buf = malloc(sizeof(char) * len);
    privc(cls)->buf_len = len;
    privc(cls)->cp_entries = NULL;
    privc(cls)->cp_entries_len = 0;
    privc(cls)->ann_cache = NULL;
    privc(cls)->ann_parsed = false;
    privc(cls)->ann_initialized = false;
    memcpy((unsigned char *) privc(cls)->buf, buf, len);

    cj_parse_offset(cls);

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
    cj_sfree(privc(ctx)->method_offsets);
    cj_sfree(privc(ctx)->field_offsets);
    cj_sfree(privc(ctx)->attr_offsets);

    if (privc(ctx)->cp_entries != NULL) {
        for (int i = 0; i < privc(ctx)->cp_entries_len; ++i) {
            cj_cp_entry_t *entry = privc(ctx)->cp_entries[i];
            if (entry == NULL) continue;
            free(entry->data);
            free(entry);
        }
        free(privc(ctx)->cp_entries);
    }

    if (privc(ctx)->field_cache != NULL) {
        for (int i = 0; i < ctx->field_count; ++i) {
            cj_sfree(privc(ctx)->field_cache[i]);
        }
        free(privc(ctx)->field_cache);
    }

    if (privc(ctx)->method_cache != NULL) {
        for (int i = 0; i < ctx->method_count; ++i) {
            cj_sfree(privc(ctx)->method_cache[i]);
        }
        free(privc(ctx)->method_cache);
    }

    if (privc(ctx)->attr_cache != NULL) {
        for (int i = 0; i < ctx->attr_count; ++i) {
            cj_sfree(privc(ctx)->attr_cache[i]);
        }
        free(privc(ctx)->attr_cache);
    }

    for (int i = 0; i < privc(ctx)->cp_len; ++i) {
        if (privc(ctx)->cp_cache[i] != NULL) {
            free(privc(ctx)->cp_cache[i]);
            privc(ctx)->cp_cache[i] = NULL;
        }
    }

    if (privc(ctx)->ann_cache != NULL) {
        for (int i = 0; i < privc(ctx)->ann_count; ++i) {
            cj_annotation_t *ann = privc(ctx)->ann_cache[i];
            if (ann->attributes_count > 0 && ann->attributes != NULL) {
                for (int j = 0; j < ann->attributes_count; ++j) {
                    cj_element_pair_t *pair = ann->attributes[j];
                    cj_sfree(pair->value);
                    cj_sfree(pair); //fixme free element
                }
            }
            cj_sfree(ann);// fixme: free element
        }
        cj_sfree(privc(ctx)->ann_cache);
    }

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
    u2 offset = privc(ctx)->cp_offsets[privc(ctx)->this_class];
    u2 name_index = cj_ru2(privc(ctx)->buf + offset);
    return cj_cp_get_str(ctx, name_index);
}


cj_field_t *cj_class_get_field(cj_class_t *ctx, u2 idx) {
    if (ctx->field_count <= 0 || idx >= ctx->field_count) {
        return NULL;
    }

    if (privc(ctx)->field_cache == NULL) {
        //初始化字段缓存
        privc(ctx)->field_cache = calloc(sizeof(cj_field_t *), ctx->field_count);
    }

    if (privc(ctx)->field_cache[idx] == NULL) {

        //按需初始化字段，并放入缓存中.

        u4 offset = privc(ctx)->field_offsets[idx];
        u2 access_flags = cj_ru2(privc(ctx)->buf + offset);
        u2 name_index = cj_ru2(privc(ctx)->buf + offset + 2);
        u2 descriptor_index = cj_ru2(privc(ctx)->buf + offset + 4);
        u2 attributes_count = cj_ru2(privc(ctx)->buf + offset + 6);

        cj_field_t *field = malloc(sizeof(cj_field_t));
        field->access_flags = access_flags;
        field->index = idx;
        field->klass = ctx;
        field->name = cj_cp_get_str(ctx, name_index);
        field->descriptor = cj_cp_get_str(ctx, descriptor_index);
        field->attribute_count = attributes_count;

        privc(ctx)->field_cache[idx] = field;
    }

    return privc(ctx)->field_cache[idx];
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

void cj_field_set_name(cj_field_t *field, const_str name) {
    u2 idx = 0;
    const_str new_name = cj_cp_put_str(field->klass, name, strlen((char *) name), &idx);
    field->name = new_name;
}

u2 cj_class_get_method_count(cj_class_t *ctx) {
    return ctx->method_count;
}

cj_method_t *cj_class_get_method(cj_class_t *ctx, u2 idx) {
    if (ctx == NULL || privc(ctx) == NULL || idx >= ctx->method_count) {
        return NULL;
    }

    if (privc(ctx)->method_cache == NULL) {
        privc(ctx)->method_cache = calloc(sizeof(cj_method_t *), ctx->method_count);
    }

    if (privc(ctx)->method_cache[idx] == NULL) {
        u4 offset = privc(ctx)->method_offsets[idx];

        u2 access_flags = cj_ru2(privc(ctx)->buf + offset);
        u2 name_index = cj_ru2(privc(ctx)->buf + offset + 2);
        u2 descriptor_index = cj_ru2(privc(ctx)->buf + offset + 4);
        u2 attributes_count = cj_ru2(privc(ctx)->buf + offset + 6);

        cj_method_t *method = malloc(sizeof(cj_method_t));
        method->access_flags = access_flags;
        method->name = cj_cp_get_str(ctx, name_index);
        method->descriptor = cj_cp_get_str(ctx, descriptor_index);
        method->klass = ctx;
        method->index = idx;
        method->attribute_count = attributes_count;
        method->priv = calloc(sizeof(cj_method_priv_t), 1);
        privm(method)->offset = offset;

        privc(ctx)->method_cache[idx] = method;
    }

    return privc(ctx)->method_cache[idx];
}

const_str cj_method_get_name(cj_method_t *method) {
    return method->name;
}

u2 cj_method_get_access_flags(cj_method_t *method) {
    return method->access_flags;
}

const_str cj_method_get_descriptor(cj_method_t *method) {
    return method->descriptor;
}

u2 cj_class_get_attribute_count(cj_class_t *ctx) {
    return ctx->attr_count;
}

cj_attribute_t *cj_class_get_attribute(cj_class_t *ctx, u2 idx) {
    if (ctx == NULL || privc(ctx) == NULL || idx >= ctx->attr_count) {
        return NULL;
    }
    if (privc(ctx)->attr_cache == NULL) {
        privc(ctx)->attr_cache = calloc(sizeof(cj_attribute_t *), ctx->attr_count);
    }

    if (privc(ctx)->attr_cache[idx] == NULL) {
        u4 offset = privc(ctx)->attr_offsets[idx];

        u2 attribute_name_index = cj_ru2(privc(ctx)->buf + offset);
        u4 attribute_length = cj_ru4(privc(ctx)->buf + offset + 2);

        cj_attribute_t *attr = malloc(sizeof(cj_attribute_t));
        attr->type_name = cj_cp_get_str(ctx, attribute_name_index);
        attr->length = attribute_length;
        attr->type = cj_attr_parse_type(attr->type_name);

        privc(ctx)->attr_cache[idx] = attr;
    }

    return privc(ctx)->attr_cache[idx];
}

cj_attr_type_t cj_attr_parse_type(const_str type_str) {
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

    if (privc(ctx)->ann_initialized) {
        return privc(ctx)->ann_count;
    }

    u2 count = cj_class_get_attribute_count(ctx);
    if (count == 0) return 0;

    u2 ann_count = 0;
    for (int i = 0; i < count; ++i) {
        cj_attribute_t *attr = cj_class_get_attribute(ctx, i);
        if (attr->type == CJ_ATTR_RuntimeVisibleAnnotations || attr->type == CJ_ATTR_RuntimeInvisibleAnnotations ||
            attr->type == CJ_ATTR_RuntimeVisibleTypeAnnotations || attr->type == CJ_ATTR_RuntimeInvisibleTypeAnnotations
                ) {
            u4 offset = privc(ctx)->attr_offsets[i];
            u2 num_annotations = cj_ru2(privc(ctx)->buf + offset + 6);
            if (num_annotations == 0) continue;

            ann_count += num_annotations;
        }
    }

    privc(ctx)->ann_count = ann_count;
    privc(ctx)->ann_initialized = true;

    return ann_count;
}

cj_annotation_t *cj_class_get_annotation(cj_class_t *ctx, u2 idx) {

    if (ctx == NULL || privc(ctx) == NULL) return NULL;
    u2 attr_count = cj_class_get_attribute_count(ctx);
    if (idx >= attr_count) return NULL;

    u2 ann_count = cj_class_get_annotation_count(ctx);
    if (idx >= ann_count) return NULL;

    //fixme: 后续通过直接在初始化时，扫描所有的注解偏移地址实现，无需多次扫描
    if (!privc(ctx)->ann_parsed || privc(ctx)->ann_cache == NULL) {

        privc(ctx)->ann_cache = malloc(sizeof(cj_annotation_t *) * ann_count);

        u2 count = cj_class_get_attribute_count(ctx);
        if (count == 0) return 0;

        u2 ann_idx = 0;
        for (int i = 0; i < count; ++i) {
            cj_attribute_t *attr = cj_class_get_attribute(ctx, i);
            if (attr->type == CJ_ATTR_RuntimeVisibleAnnotations ||
                attr->type == CJ_ATTR_RuntimeInvisibleAnnotations) {

                u4 offset = privc(ctx)->attr_offsets[i];
                u2 num_annotations = cj_ru2(privc(ctx)->buf + offset + 6);
                if (num_annotations == 0) continue;
                offset += 8;

                for (int j = 0; j < num_annotations; ++j) {
                    cj_annotation_t *ann = cj_annotation_parse(ctx, privc(ctx)->buf, &offset);
                    privc(ctx)->ann_cache[ann_idx++] = ann;
                }

                ann_count += num_annotations;
            } else if (attr->type == CJ_ATTR_RuntimeVisibleTypeAnnotations ||
                       attr->type == CJ_ATTR_RuntimeInvisibleTypeAnnotations) {
                u4 offset = privc(ctx)->attr_offsets[i];
                u2 num_annotations = cj_ru2(privc(ctx)->buf + offset + 6);
                if (num_annotations == 0) continue;

                ann_count += num_annotations;
            }
        }
    }

    return privc(ctx)->ann_cache[idx];
}

u4 cj_cp_get_u4(cj_class_t *ctx, u2 idx) {
    return 0;
}

u8 cj_cp_get_u8(cj_class_t *ctx, u2 idx) {
    return 0;
}

u2 cj_method_get_attribute_count(cj_method_t *method) {

    return method->attribute_count;
}

cj_attribute_t *cj_method_get_attribute(cj_method_t *method, u2 idx) {
    if (method->attribute_count <= 0) return NULL;

    cj_class_t *ctx = method->klass;

    if (privm(method)->attribute_offsets == NULL) {
        cj_attribute_parse_offsets(privc(ctx)->buf, privm(method)->offset + 8,
                                   &privm(method)->attribute_offsets,
                                   method->attribute_count);
    }

    if (privm(method)->attribute_cache == NULL) {
        privm(method)->attribute_cache = calloc(sizeof(cj_attribute_t *), method->attribute_count);
    }

    if (privm(method)->attribute_cache[idx] == NULL) {

        u4 offset = privm(method)->attribute_offsets[idx];

        u2 attribute_name_index = cj_ru2(privc(ctx)->buf + offset);
        u4 attribute_length = cj_ru4(privc(ctx)->buf + offset + 2);

        cj_attribute_t *attr = malloc(sizeof(cj_attribute_t));
        attr->type_name = cj_cp_get_str(ctx, attribute_name_index);
        attr->length = attribute_length;
        attr->type = cj_attr_parse_type(attr->type_name);

        privm(method)->attribute_cache[idx] = attr;
    }

    return privm(method)->attribute_cache[idx];
}


