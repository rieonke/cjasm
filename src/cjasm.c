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

    if (privc(ctx)->cpool->entries != NULL) {
        for (int i = 0; i < privc(ctx)->cpool->entries_len; ++i) {
            cj_cp_entry_t *entry = privc(ctx)->cpool->entries[i];
            if (entry == NULL) continue;
            free(entry->data);
            free(entry);
        }
        free(privc(ctx)->cpool->entries);
    }

    for (int i = 0; i < privc(ctx)->cpool->length; ++i) {
        if (privc(ctx)->cpool->cache[i] != NULL) {
            free(privc(ctx)->cpool->cache[i]);
            privc(ctx)->cpool->cache[i] = NULL;
        }
    }

    if (privc(ctx)->annotation_set != NULL) {
        cj_annotation_set_free(privc(ctx)->annotation_set);
    }
    cj_sfree((char *) ctx->name);

    cj_sfree(privc(ctx)->cpool->cache);
    cj_sfree(privc(ctx));
    cj_sfree(ctx);
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
    return 0;
}

u8 cj_cp_get_u8(cj_class_t *ctx, u2 idx) {
    return 0;
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


