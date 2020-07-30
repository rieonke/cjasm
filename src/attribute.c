//
// Created by Rieon Ke on 2020/7/24.
//

#include "class.h"
#include "attribute.h"
#include "cpool.h"
#include "annotation.h"

struct cj_attribute_priv_s {
    u4 dirty;
    u4 head;
    cj_pointer data;
};

#define priv(a) ((cj_attribute_priv_t*)(a->priv))

CJ_INTERNAL void cj_attribute_parse_offsets(buf_ptr ptr, u4 offset, u4 **offsets, u4 len) {
    if (len == 0) {
        return;
    }

    if (*offsets == NULL) {
        *offsets = malloc(sizeof(u4) * len);
    }

    for (int i = 0; i < len; ++i) {
        *offsets[i] = offset;
        /*
         * attribute_info {
         *    u2 attribute_name_index;
         *    u4 attribute_length;
         *    u1 info[attribute_length];
         * }
         *
         */
        u4 attribute_length = cj_ru4(ptr + offset + 2);
        offset += 6 + attribute_length;
    }

}

CJ_INTERNAL void cj_attribute_free(cj_attribute_t *attr) {
    if (attr == NULL) return;
    if (priv(attr) != NULL) {
        cj_sfree(priv(attr));
    }
    cj_sfree(attr);
}

CJ_INTERNAL cj_attribute_t *cj_attribute_group_get(cj_class_t *ctx, cj_attribute_group_t *set, u2 idx) {

    if (ctx == NULL || set == NULL || set->count <= idx) {
        return NULL;
    }

    if (set->fetched == NULL) {
        set->fetched = calloc(sizeof(cj_attribute_t *), set->count);
    }

    if (set->fetched[idx] == NULL) {

        u4 head = set->heads[idx];

        buf_ptr buf = cj_class_get_buf_ptr(ctx, head);
        u2 attribute_name_index = cj_ru2(buf);
        u4 attribute_length = cj_ru4(buf + 2);

        cj_attribute_priv_t *priv = malloc(sizeof(cj_attribute_priv_t));
        priv->dirty = CJ_DIRTY_CLEAN;
        priv->head = head;

        cj_attribute_t *attr = malloc(sizeof(cj_attribute_t));
        attr->type_name = cj_cp_get_str(ctx, attribute_name_index);
        attr->length = attribute_length;
        attr->type = cj_attr_parse_type(attr->type_name);
        attr->priv = priv;

        set->fetched[idx] = attr;
    }

    return set->fetched[idx];
}


cj_mem_buf_t *cj_attribute_to_buf(cj_class_t *cls, cj_attribute_t *attr) {
    if (cls == NULL || attr == NULL || priv(attr) == NULL) return NULL;

    cj_mem_buf_t *buf = cj_mem_buf_new();

    if (priv(attr)->dirty == CJ_DIRTY_CLEAN) { //untouched, just copy the original bytecodes
        buf_ptr start = cj_class_get_buf_ptr(cls, priv(attr)->head);
        cj_mem_buf_write_str(buf, (char *) start, attr->length + 6); //因为当前长度不包括前六个字节，在此补齐
        cj_mem_buf_flush(buf);
        return buf;
    }
    /*
       u2 attribute_name_index;
       u4 attribute_length;
       u2 num_annotations;
       annotation annotations[num_annotations];
    */

    const char *type_str = cj_attr_type_to_str(attr->type);
    u2 type_idx = 0;
    cj_cp_put_str(cls, (const_str) type_str, strlen(type_str), &type_idx);

    u4 attr_len = 0;
    cj_mem_buf_write_u2(buf, type_idx);
    cj_mem_buf_write_u4(buf, /*attribute_length*/ 0);

    switch (attr->type) {
        case CJ_ATTR_NONE:
            break;
        case CJ_ATTR_AnnotationDefault:
            break;
        case CJ_ATTR_BootstrapMethods:
            break;
        case CJ_ATTR_Code:
            break;
        case CJ_ATTR_ConstantValue:
            break;
        case CJ_ATTR_Deprecated:
            break;
        case CJ_ATTR_EnclosingMethod:
            break;
        case CJ_ATTR_Exceptions:
            break;
        case CJ_ATTR_InnerClasses:
            break;
        case CJ_ATTR_LineNumberTable:
            break;
        case CJ_ATTR_LocalVariableTable:
            break;
        case CJ_ATTR_LocalVariableTypeTable:
            break;
        case CJ_ATTR_MethodParameters:
            break;
        case CJ_ATTR_Module:
            break;
        case CJ_ATTR_ModuleMainClass:
            break;
        case CJ_ATTR_ModulePackages:
            break;
        case CJ_ATTR_NestHost:
            break;
        case CJ_ATTR_NestMembers:
            break;
        case CJ_ATTR_RuntimeInvisibleParameterAnnotations:
            break;
        case CJ_ATTR_RuntimeInvisibleTypeAnnotations:
            break;
        case CJ_ATTR_RuntimeVisibleAnnotations:
        case CJ_ATTR_RuntimeInvisibleAnnotations: {
            //将当前attribute转换为一个annotation_group
            cj_annotation_group_t *ag = priv(attr)->data;
            cj_mem_buf_t *ann_buf =
                    cj_annotation_group_to_buf(cls, ag, attr->type == CJ_ATTR_RuntimeVisibleAnnotations);
            if (ann_buf == NULL) { //如果当前一个注解都没有，那么该属性也就没有意义了，直接返回空，删除该属性。
                cj_mem_buf_free(buf);
                return NULL;
            }
            cj_mem_buf_write_buf(buf, ann_buf);
            attr_len += ann_buf->length;
            cj_mem_buf_free(ann_buf);
            break;
        }
        case CJ_ATTR_RuntimeVisibleParameterAnnotations:
            break;
        case CJ_ATTR_RuntimeVisibleTypeAnnotations:
            break;
        case CJ_ATTR_Signature:
            break;
        case CJ_ATTR_SourceDebugExtension:
            break;
        case CJ_ATTR_SourceFile:
            break;
        case CJ_ATTR_StackMapTable:
            break;
        case CJ_ATTR_Synthetic:
            break;
    }

    cj_mem_buf_flush(buf);
    cj_wu4(buf->data + 2, attr_len);
    return buf;
}

cj_mem_buf_t *cj_attribute_group_to_buf(cj_class_t *cls, cj_attribute_group_t *group) {
    if (cls == NULL || group == NULL) return NULL;
    cj_mem_buf_t *buf = cj_mem_buf_new();
    u2 attr_count = 0;

    cj_mem_buf_write_u2(buf, attr_count);

    for (int i = 0; i < group->count; ++i) {
        cj_attribute_t *attribute = cj_attribute_group_get(cls, group, i);
        if (attribute == NULL) continue;
        cj_mem_buf_t *attr_buf = cj_attribute_to_buf(cls, attribute);
        if (attr_buf != NULL) {
            cj_mem_buf_write_buf(buf, attr_buf);
            cj_mem_buf_free(attr_buf);
            ++attr_count;
        }
    }

    cj_mem_buf_flush(buf);
    cj_wu2(buf->data, attr_count);

    return buf;
}

CJ_INTERNAL void cj_attribute_group_free(cj_attribute_group_t *set) {

    if (set == NULL) return;
    cj_sfree(set->heads);
    cj_sfree(set->tails);

    if (set->fetched != NULL) {
        for (int i = 0; i < set->count; ++i) {
            cj_attribute_free(set->fetched[i]);
        }
        cj_sfree(set->fetched);
    }
    free(set);
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

const char *cj_attr_type_to_str(enum cj_attr_type type) {

    switch (type) {
        case CJ_ATTR_NONE:
            return "NONE";
        case CJ_ATTR_AnnotationDefault:
            return "AnnotationDefault";
        case CJ_ATTR_BootstrapMethods:
            return "BootstrapMethods";
        case CJ_ATTR_Code:
            return "Code";
        case CJ_ATTR_ConstantValue:
            return "ConstantValue";
        case CJ_ATTR_Deprecated:
            return "Deprecated";
        case CJ_ATTR_EnclosingMethod:
            return "EnclosingMethod";
        case CJ_ATTR_Exceptions:
            return "Exceptions";
        case CJ_ATTR_InnerClasses:
            return "InnerClasses";
        case CJ_ATTR_LineNumberTable:
            return "LineNumberTable";
        case CJ_ATTR_LocalVariableTable:
            return "LocalVariableTable";
        case CJ_ATTR_LocalVariableTypeTable:
            return "LocalVariableTypeTable";
        case CJ_ATTR_MethodParameters:
            return "MethodParameters";
        case CJ_ATTR_Module:
            return "Module";
        case CJ_ATTR_ModuleMainClass:
            return "ModuleMainClass";
        case CJ_ATTR_ModulePackages:
            return "ModulePackages";
        case CJ_ATTR_NestHost:
            return "NestHost";
        case CJ_ATTR_NestMembers:
            return "NestMembers";
        case CJ_ATTR_RuntimeInvisibleAnnotations:
            return "RuntimeInvisibleAnnotations";
        case CJ_ATTR_RuntimeInvisibleParameterAnnotations:
            return "RuntimeInvisibleParameterAnnotations";
        case CJ_ATTR_RuntimeInvisibleTypeAnnotations:
            return "RuntimeInvisibleTypeAnnotations";
        case CJ_ATTR_RuntimeVisibleAnnotations:
            return "RuntimeVisibleAnnotations";
        case CJ_ATTR_RuntimeVisibleParameterAnnotations:
            return "RuntimeVisibleParameterAnnotations";
        case CJ_ATTR_RuntimeVisibleTypeAnnotations:
            return "RuntimeVisibleTypeAnnotations";
        case CJ_ATTR_Signature:
            return "Signature";
        case CJ_ATTR_SourceDebugExtension:
            return "SourceDebugExtension";
        case CJ_ATTR_SourceFile:
            return "SourceFile";
        case CJ_ATTR_StackMapTable:
            return "StackMapTable";
        case CJ_ATTR_Synthetic:
            return "Synthetic";
    }

}


u4 cj_attribute_get_head_offset(cj_attribute_t *attr) {
    return priv(attr)->head;
}

void cj_attribute_set_data(cj_attribute_t *attr, void *data) {
    priv(attr)->data = data;
}


void cj_attribute_mark_dirty(cj_attribute_t *attr) {
    priv(attr)->dirty |= CJ_DIRTY_DIRTY;
}

cj_attribute_group_t *cj_attribute_group_new(u2 count, u4 *heads, u4 *tails) {
    cj_attribute_group_t *group = malloc(sizeof(cj_attribute_group_t));
    group->count = count;
    group->fetched = NULL;
    group->heads = heads;
    group->tails = tails;

    return group;
}
