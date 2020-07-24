//
// Created by Rieon Ke on 2020/7/24.
//

#include "attribute.h"

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
    if (priva(attr) != NULL) {
        cj_sfree(priva(attr));
    }
    cj_sfree(attr);
}

CJ_INTERNAL cj_attribute_t *cj_attribute_group_get(cj_class_t *ctx, cj_attribute_group_t *set, u2 idx) {

    if (ctx == NULL || privc(ctx) == NULL || set == NULL || set->count <= idx) {
        return NULL;
    }

    if (set->cache == NULL) {
        set->cache = calloc(sizeof(cj_attribute_t *), set->count);
    }

    if (set->cache[idx] == NULL) {

        u4 offset = set->offsets[idx];

        u2 attribute_name_index = cj_ru2(privc(ctx)->buf + offset);
        u4 attribute_length = cj_ru4(privc(ctx)->buf + offset + 2);

        cj_attribute_priv_t *priv = malloc(sizeof(cj_attribute_priv_t));
        priv->offset = offset;

        cj_attribute_t *attr = malloc(sizeof(cj_attribute_t));
        attr->type_name = cj_cp_get_str(ctx, attribute_name_index);
        attr->length = attribute_length;
        attr->type = cj_attr_parse_type(attr->type_name);
        attr->priv = priv;

        set->cache[idx] = attr;
    }

    return set->cache[idx];
}

CJ_INTERNAL void cj_attribute_group_free(cj_attribute_group_t *set) {

    if (set == NULL) return;
    cj_sfree(set->offsets);

    if (set->cache != NULL) {
        for (int i = 0; i < set->count; ++i) {
            cj_attribute_free(set->cache[i]);
        }
        cj_sfree(set->cache);
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

