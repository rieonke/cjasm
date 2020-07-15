//
// Created by Rieon Ke on 2020/7/15.
//

#include "util.h"

CJ_INTERNAL const_str cj_cp_put_str(cj_class_t *ctx, const_str name, size_t len, u2 *index) {
    // 检查现有的常量池中是否有当前字符串
    // 如果有，则直接返回现有的字符串
    // 如果不存在，则将该字符串放置于新的常量池中
    for (int i = 1; i < privc(ctx)->cp_len; ++i) {
        u1 type = privc(ctx)->cp_types[i];
        if (type == CONSTANT_Utf8) {
            const unsigned char *str = cj_cp_get_str(ctx, i);
            if (strncmp((char *) str, (char *) name, len) == 0) {
                if (index != NULL) *index = i;
                return str;
            }
        } else if (type == CONSTANT_Long || type == CONSTANT_Double) {
            i++;
        }
    }

    u2 cur_idx = privc(ctx)->cp_entries_len++;
    if (privc(ctx)->cp_entries == NULL) {
        privc(ctx)->cp_entries = malloc(sizeof(cj_cp_entry_t *));
    } else {
        privc(ctx)->cp_entries = realloc(privc(ctx)->cp_entries, sizeof(cj_cp_entry_t *) * privc(ctx)->cp_entries_len);
    }

    cj_cp_entry_t *entry = malloc(sizeof(cj_cp_entry_t));
    entry->tag = CONSTANT_Utf8;
    entry->len = len;
    entry->data = (unsigned char *) strndup((char *) name, len);

    if (index != NULL) {
        *index = cur_idx + privc(ctx)->cp_len - 1;
    }

    privc(ctx)->cp_entries[cur_idx] = entry;
    return entry->data;
}

CJ_INTERNAL cj_annotation_t *cj_annotation_parse(cj_class_t *ctx, buf_ptr attr_ptr, u4 *out_offset) {

    u4 offset = out_offset == NULL ? 0 : *out_offset;
    cj_annotation_t *annotation = NULL;
    cj_element_pair_t **pairs = NULL;

    /*
     * annotation {
     *     u2 type_index;
     *     u2 num_element_value_pairs;
     *     {   u2            element_name_index;
     *         element_value value;
     *     } element_value_pairs[num_element_value_pairs];
     * }
     *
     */
    u2 type_index = cj_ru2(attr_ptr + offset);
    u2 num_pairs = cj_ru2(attr_ptr + offset + 2);

    offset += 4;

    if (num_pairs > 0) {
        pairs = malloc(sizeof(cj_element_pair_t *) * num_pairs);
        for (int j = 0; j < num_pairs; ++j) {

            cj_element_pair_t *pair = malloc(sizeof(cj_element_pair_t));

            u2 element_name_index = cj_ru2(attr_ptr + offset);
            offset += 2;
            cj_element_t *element = cj_annotation_parse_element_value(ctx, attr_ptr, &offset);
            pair->name = cj_cp_get_str(ctx, element_name_index);
            pair->value = element;

            pairs[j] = pair;
        }
    }

    annotation = malloc(sizeof(cj_annotation_t));
    annotation->type_name = cj_cp_get_str(ctx, type_index);
    annotation->attributes_count = num_pairs;
    annotation->attributes = pairs;

    if (out_offset != NULL) *out_offset = offset;
    return annotation;
}

CJ_INTERNAL cj_element_t *cj_annotation_parse_element_value(cj_class_t *ctx, buf_ptr ev_ptr, u4 *out_offset) {

    u4 offset = out_offset == NULL ? 0 : *out_offset;
    cj_element_t *ev = calloc(sizeof(cj_element_t), 1);

    /*
     * element_value {
     *     u1 tag;
     *     union {
     *         u2 const_value_index;
     *         {   u2 type_name_index;
     *             u2 const_name_index;
     *         } enum_const_value;
     *         u2 class_info_index;
     *         annotation annotation_value;
     *         {   u2            num_values;
     *             element_value values[num_values];
     *         } array_value;
     *     } value;
     * }
     *
     *
     *  +-----+------------+-------------------------------------+
     *  | tag |    Type    |    value Item     |  Constant Type   |
     *  +-----+------------+-------------------+------------------+
     *  | B   | byte       | const_value_index | CONSTANT_Integer |
     *  | C   | char       | const_value_index | CONSTANT_Integer |
     *  | D   | double     | const_value_index | CONSTANT_Double  |
     *  | F   | float      | const_value_index | CONSTANT_Float   |
     *  | I   | int        | const_value_index | CONSTANT_Integer |
     *  | J   | long       | const_value_index | CONSTANT_Long    |
     *  | S   | short      | const_value_index | CONSTANT_Integer |
     *  | Z   | boolean    | const_value_index | CONSTANT_Integer |
     *  | s   | String     | const_value_index | CONSTANT_Utf8    |
     *  | e   | Enum       | enum_const_value  | Not applicable   |
     *  | c   | Class      | class_info_index  | Not applicable   |
     *  | @   | Annotation | annotation_value  | Not applicable   |
     *  | [   | Array      | array_value       | Not applicable   |
     *  +-----+------------+-------------------+------------------+
     */

    u1 tag = cj_ru1(ev_ptr + offset++);
    ev->tag = tag;
    switch (tag) {
        case 'B': /*byte*/
        case 'C': /*char*/
        case 'I': /*int*/
        case 'S': /*short*/
        case 'Z': /*boolean*/
        case 'F': /*float*/
        {
            u2 idx = cj_ru2(ev_ptr + offset);
            u4 val = cj_cp_get_u4(ctx, idx);
            ev->const_num = val;
            break;
        }
        case 'D': /*double*/
        case 'J': /*long*/
        {
            u2 idx = cj_ru2(ev_ptr + offset);
            u8 val = cj_cp_get_u8(ctx, idx);
            ev->const_num = val;
            break;
        }
        case 's':/*string*/
        {
            u2 idx = cj_ru2(ev_ptr + offset);
            ev->const_str = cj_cp_get_str(ctx, idx);
            offset += 2;
            break;
        }
        case 'e': /*enum*/
        {
            u2 type_name_idx = cj_ru2(ev_ptr + offset);
            u2 const_name_idx = cj_ru2(ev_ptr + offset + 2);
            offset += 4;

            ev->type_name = cj_cp_get_str(ctx, type_name_idx);
            ev->const_name = cj_cp_get_str(ctx, const_name_idx);
            break;
        }
        case 'c': /*class*/
        {
            u2 class_idx = cj_ru2(ev_ptr + offset);
            offset += 2;
            ev->class_info_index = class_idx;
            break;
        }
        case '@': /*annotation*/
        {
            ev->annotation = cj_annotation_parse(ctx, ev_ptr, &offset); //fixme check error
            break;
        }
        case '[': /*array*/
        {
            u2 ev_count = cj_ru2(ev_ptr + offset);
            offset += 2;
            cj_element_t **element_values = NULL;

            if (ev_count > 0) {
                element_values = malloc(sizeof(cj_element_t) * ev_count);
                for (int i = 0; i < ev_count; ++i) {
                    element_values[i] = cj_annotation_parse_element_value(ctx, ev_ptr, &offset); //fixme check error
                }
            }
            ev->element_count = ev_count;
            ev->elements = element_values;
        }
        default:
            cj_sfree(ev);
            fprintf(stderr, "ERROR: invalid annotation, unknown element value tag: %c\n", tag);
            return NULL;
    }


    if (out_offset != NULL)
        *out_offset = offset;

    return ev;
}

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

CJ_INTERNAL cj_attribute_t *cj_attribute_set_get(cj_class_t *ctx, cj_attribute_set_t *set, u2 idx) {

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

        cj_attribute_t *attr = malloc(sizeof(cj_attribute_t));
        attr->type_name = cj_cp_get_str(ctx, attribute_name_index);
        attr->length = attribute_length;
        attr->type = cj_attr_parse_type(attr->type_name);

        set->cache[idx] = attr;
    }

    return set->cache[idx];
}

CJ_INTERNAL void cj_attribute_set_free(cj_attribute_set_t *set) {

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

CJ_INTERNAL void cj_attribute_free(cj_attribute_t *attr) {
    cj_sfree(attr);
}

CJ_INTERNAL void cj_method_free(cj_method_t *method) {
    if (method == NULL) return;
    cj_sfree(privm(method));
    cj_sfree(method);
}


CJ_INTERNAL void cj_element_free(cj_element_t *element) {
    if (element == NULL) return;
    switch (element->tag) {
        case '@': /*annotation*/
            cj_annotation_free(element->annotation);
            break;
        case '[': /*array*/
            if (element->elements != NULL) {
                for (int i = 0; i < element->element_count; ++i) {
                    cj_element_free(element->elements[i]);
                }
            }
        default:
            break;
    }

    cj_sfree(element);
}

CJ_INTERNAL void cj_annotation_free(cj_annotation_t *ann) {
    if (ann == NULL) return;

    if (ann->attributes != NULL) {

        for (int i = 0; i < ann->attributes_count; ++i) {
            cj_element_pair_t *pair = ann->attributes[i];
            if (pair == NULL) continue;
            cj_element_free(pair->value);
            cj_sfree(pair);
        }
        cj_sfree(ann->attributes);
    }
    cj_sfree(ann);


}


CJ_INTERNAL cj_method_t *cj_method_set_get(cj_class_t *ctx, cj_method_set_t *set, u2 idx) {

    if (set->cache == NULL) {
        set->cache = calloc(sizeof(cj_method_t *), ctx->method_count);
    }

    if (set->cache[idx] == NULL) {
        u4 offset = set->offsets[idx];

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
        privm(method)->attribute_set = privc(ctx)->method_attribute_sets[idx];

        set->cache[idx] = method;
    }

    return set->cache[idx];
}

CJ_INTERNAL void cj_method_set_free(cj_method_set_t *set) {
    if (set == NULL) return;
    cj_sfree(set->offsets);
    if (set->cache != NULL) {
        for (int i = 0; i < set->count; ++i) {
            cj_method_free(set->cache[i]);
        }
    }
    cj_sfree(set->cache);
    cj_sfree(set);
}

CJ_INTERNAL cj_field_t *cj_field_set_get(cj_class_t *ctx, cj_field_set_t *set, u2 idx) {

    if (set->cache == NULL) {
        //初始化字段缓存
        set->cache = calloc(sizeof(cj_field_t *), ctx->field_count);
    }

    if (set->cache[idx] == NULL) {
        //按需初始化字段，并放入缓存中.
        u4 offset = set->offsets[idx];
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

        set->cache[idx] = field;
    }

    return set->cache[idx];

}

CJ_INTERNAL void cj_field_set_free(cj_field_set_t *set) {

    if (set == NULL) return;
    cj_sfree(set->offsets);
    if (set->cache != NULL) {
        for (int i = 0; i < set->count; ++i) {
            cj_sfree(set->cache[i]);
        }
    }
    cj_sfree(set->cache);
    cj_sfree(set);
}

