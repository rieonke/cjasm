//
// Created by Rieon Ke on 2020/8/1.
//

#include "def.h"
#include "code.h"
#include "attribute.h"
#include "method.h"
#include "class.h"
#include "util.h"
#include "mem_buf.h"

#define CODE_COMMON_CHECK(code)  if (code == NULL || code->method == NULL ||code->method->klass == NULL) return false


cj_attribute_group_t *cj_code_get_attribute_group(cj_code_t *code) {
    /*
     * LineNumberTable --done
     * LocalVariableTable
     * LocalVariableTypeTable
     * StackMapTable
     * RuntimeVisibleTypeAnnotations
     * RuntimeInvisibleTypeAnnotations
     *
     */
    return code->attr_group;
}

cj_exception_tab_t *cj_code_get_exception_table(cj_code_t *code) {
    return code->exception_tab;
}

cj_code_t *cj_code_attr_parse(cj_method_t *method, cj_attribute_t *attr) {
    if (method == NULL || attr == NULL) return NULL;

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
    u4 offset = cj_attribute_get_head_offset(attr);

    if (offset == 0) return NULL;
    buf_ptr buf = cj_class_get_buf_ptr(method->klass, 0);

    u2 max_stack = cj_ru2(buf + offset + 6);
    u2 max_locals = cj_ru2(buf + offset + 8);
    u4 code_length = cj_ru4(buf + offset + 10);
    u2 head = offset += 14;
    offset += code_length;

    u2 attributes_count = 0;
    cj_attribute_group_t *attr_group = NULL;
    u2 exc_tab_len = cj_ru2(buf + offset);
    cj_exception_tab_t *exc_tab = NULL;
    offset += 2;

    if (exc_tab_len > 0) {
        cj_exception_t **excs = malloc(sizeof(cj_exception_t *) * exc_tab_len);

        exc_tab = malloc(sizeof(cj_exception_tab_t));
        exc_tab->exceptions = excs;
        exc_tab->length = exc_tab_len;

        for (int i = 0; i < exc_tab_len; ++i) {
            u2 start_pc = cj_ru2(buf + offset);
            u2 end_pc = cj_ru2(buf + offset + 2);
            u2 handler_pc = cj_ru2(buf + offset + 4);
            u2 catch_type = cj_ru2(buf + offset + 6);

            cj_exception_t *exc = malloc(sizeof(cj_exception_t));
            exc->start_pc = start_pc;
            exc->end_pc = end_pc;
            exc->handler_pc = handler_pc;
            exc->catch_type = catch_type;

            excs[i] = exc;
            offset += 8;
        }
    }
    attributes_count = cj_ru2(buf + offset);
    offset += 2;

    u4 *attribute_heads = NULL;
    u4 *attribute_tails = NULL;

    if (attributes_count > 0) {
        attribute_heads = malloc(sizeof(u4) * attributes_count);
        attribute_tails = malloc(sizeof(u4) * attributes_count);

        for (int j = 0; j < attributes_count; ++j) {
            attribute_heads[j] = offset;
            u4 attribute_length = cj_ru4(buf + offset + 2);
            offset += attribute_length + 6;
            attribute_tails[j] = offset;
        }

        attr_group = cj_attribute_group_new(attributes_count, attribute_heads, attribute_tails);
    }


    cj_code_t *code = malloc(sizeof(cj_code_t));
    code->head = head;
    code->length = code_length;
    code->max_stack = max_stack;
    code->max_locals = max_locals;
    code->method = method;
    code->attr = attr;
    code->exception_tab = exc_tab;
    code->attr_group = attr_group;
    code->line_number_tab = NULL;
    code->local_var_tab = NULL;
    code->local_var_type_tab = NULL;
    code->stack_map_tab = NULL;

    cj_attribute_set_data(attr, code);

    return code;
}

cj_line_number_tab_t *cj_code_get_line_number_table(cj_code_t *code) {
    if (code == NULL || code->method == NULL ||
        code->method->klass == NULL || code->attr_group == NULL || code->attr_group->count == 0)
        return NULL;

    /**
     * LineNumberTable_attribute {
     *      u2 attribute_name_index;
     *      u4 attribute_length;
     *      u2 line_number_table_length;
     *      {   u2 start_pc;
     *          u2 line_number;	
     *      } line_number_table[line_number_table_length];
     *  }
     *  
     */
    if (code->line_number_tab == NULL) {
        buf_ptr ptr = cj_class_get_buf_ptr(code->method->klass, 0);
        for (int i = 0; i < code->attr_group->count; ++i) {
            cj_attribute_t *attr = cj_attribute_group_get(code->method->klass, code->attr_group, i);
            if (attr->type == CJ_ATTR_LineNumberTable) {
                u4 offset = cj_attribute_get_head_offset(attr) + 6;
                u2 len = cj_ru2(ptr + offset);
                offset += 2;

                cj_line_number_tab_t *tab = malloc(sizeof(cj_line_number_tab_t));
                cj_line_number_t **numbers = NULL;
                if (len > 0) {
                    numbers = malloc(sizeof(cj_line_number_t *) * len);
                    for (int j = 0; j < len; ++j) {
                        cj_line_number_t *num = malloc(sizeof(cj_line_number_t));
                        u2 start_pc = cj_ru2(ptr + offset);
                        u2 line_number = cj_ru2(ptr + offset + 2);

                        num->start_pc = start_pc;
                        num->number = line_number;
                        numbers[j] = num;

                        offset += 4;
                    }
                }

                tab->line_numbers = numbers;
                tab->length = len;
                code->line_number_tab = tab;

                break;
            }
        }
    }

    return code->line_number_tab;
}

void cj_code_free(cj_code_t *code) {
    if (code == NULL) return;
    cj_attribute_group_free(code->attr_group);
    if (code->line_number_tab != NULL && code->line_number_tab->line_numbers != NULL) {
        for (int i = 0; i < code->line_number_tab->length; ++i) {
            cj_sfree(code->line_number_tab->line_numbers[i]);
        }
        cj_sfree(code->line_number_tab->line_numbers);
    }
    cj_sfree(code->line_number_tab);

    if (code->exception_tab != NULL && code->exception_tab->exceptions != NULL) {
        for (int i = 0; i < code->exception_tab->length; ++i) {
            cj_sfree(code->exception_tab->exceptions[i]);
        }
        cj_sfree(code->exception_tab->exceptions);
    }
    cj_sfree(code->exception_tab);

    if (code->local_var_tab != NULL && code->local_var_tab->local_vars != NULL) {
        for (int i = 0; i < code->local_var_tab->length; ++i) {
            cj_sfree(code->local_var_tab->local_vars[i]);
        }
        cj_sfree(code->local_var_tab->local_vars);
    }
    cj_sfree(code->local_var_tab);

    if (code->local_var_type_tab != NULL && code->local_var_type_tab->types != NULL) {
        for (int i = 0; i < code->local_var_type_tab->length; ++i) {
            cj_sfree(code->local_var_type_tab->types[i]);
        }
        cj_sfree(code->local_var_type_tab->types);
    }
    cj_sfree(code->local_var_type_tab);

    if (code->stack_map_tab != NULL && code->stack_map_tab->frames != NULL) {
        for (int i = 0; i < code->stack_map_tab->length; ++i) {
            cj_sfree(code->stack_map_tab->frames[i]);
        }
        cj_sfree(code->stack_map_tab->frames);
    }
    cj_sfree(code->stack_map_tab);


    cj_sfree(code);
}

bool cj_code_remove_stack_map_tab(cj_code_t *code) {
    if (code == NULL || code->method == NULL || code->method->klass == NULL) {
        return false;
    }

    cj_attribute_group_t *attr_group = cj_code_get_attribute_group(code);
    if (attr_group == NULL) return false;

    for (int i = 0; i < attr_group->count; ++i) {
        cj_attribute_t *attr = cj_attribute_group_get(code->method->klass, attr_group, i);
        if (attr->type == CJ_ATTR_StackMapTable) {
            cj_attribute_mark_dirty(attr, CJ_DIRTY_REMOVE);
            code->dirty = CJ_DIRTY_ATTR;
            return true;
        }
    }

    return false;
}

bool cj_code_write_buf(cj_code_t *code, cj_mem_buf_t *buf) {
    if (code == NULL || code->method == NULL || code->method->klass == NULL) return false;

    /*
     * Code_attribute {
     *     u2 attribute_name_index;
     *     u4 attribute_length;
     *     u2 max_stack;
     *     u2 max_locals;
     *     u4 code_length;
     *     u1 code[code_length];
     *     u2 exception_table_length;
     *     {   u2 start_pc;
     *         u2 end_pc;
     *         u2 handler_pc;
     *         u2 catch_type;
     *     } exception_table[exception_table_length];
     *     u2 attributes_count;
     *     attribute_info attributes[attributes_count];
     * }
     * 
     */

    cj_debug("writing code for method %s%s\n", code->method->name, code->method->descriptor);

    cj_class_t *cls = code->method->klass;
    buf_ptr buf_ptr = cj_class_get_buf_ptr(cls, 0);
    cj_mem_buf_pos_t *exp_len_pos = NULL;

    cj_mem_buf_write_u2(buf, code->max_stack);
    cj_mem_buf_write_u2(buf, code->max_locals);

    //todo only if code clean
    cj_mem_buf_write_u4(buf, code->length);
    cj_mem_buf_write_str(buf, (char *) buf_ptr + code->head, code->length);

    exp_len_pos = cj_mem_buf_pos(buf);
    cj_mem_buf_write_u2(buf, /*exception_table_length*/0);
    if (code->exception_tab != NULL && code->exception_tab->length > 0) {
        u2 exp_len = 0;
        for (int i = 0; i < code->exception_tab->length; ++i) {
            cj_exception_t *exp = code->exception_tab->exceptions[i];
            if (exp == NULL) continue;
            cj_mem_buf_write_u2(buf, exp->start_pc);
            cj_mem_buf_write_u2(buf, exp->end_pc);
            cj_mem_buf_write_u2(buf, exp->handler_pc);
            cj_mem_buf_write_u2(buf, exp->catch_type);
            ++exp_len;
        }
        cj_mem_buf_pos_wu2(exp_len_pos, exp_len);
    }

    cj_attribute_group_t *group = cj_code_get_attribute_group(code);
    if (group == NULL) {
        cj_mem_buf_write_u2(buf, /*attributes_count*/0);
    } else {
        cj_attribute_group_write_buf(cls, group, buf);
    }

    return true;
}

void cj_code_mark_dirty(cj_code_t *code, u4 flags) {
    cj_attribute_mark_dirty(code->attr, CJ_DIRTY_CODE);
    cj_method_mark_dirty(code->method, CJ_DIRTY_CODE);
    code->dirty |= flags;
}

cj_local_var_tab_t *cj_code_get_local_var_table(cj_code_t *code) {
    CODE_COMMON_CHECK(code);
    if (code->local_var_tab == NULL) {

        /**
         * LocalVariableTable_attribute {
         *     u2 attribute_name_index;
         *     u4 attribute_length;
         *     u2 local_variable_table_length;
         *     {   u2 start_pc;
         *         u2 length;
         *         u2 name_index;
         *         u2 descriptor_index;
         *         u2 index;
         *     } local_variable_table[local_variable_table_length];
         * }
         *
         */

        buf_ptr ptr = cj_class_get_buf_ptr(code->method->klass, 0);
        for (int i = 0; i < code->attr_group->count; ++i) {
            cj_attribute_t *attr = cj_attribute_group_get(code->method->klass, code->attr_group, i);
            if (attr->type == CJ_ATTR_LocalVariableTable) {
                u4 offset = cj_attribute_get_head_offset(attr) + 6;
                u2 len = cj_ru2(ptr + offset);
                offset += 2;

                cj_local_var_tab_t *tab = malloc(sizeof(cj_local_var_tab_t));
                cj_local_var_t **vars = NULL;
                if (len > 0) {
                    vars = malloc(sizeof(cj_local_var_t *) * len);
                    for (int j = 0; j < len; ++j) {
                        cj_local_var_t *var = malloc(sizeof(cj_local_var_t));
                        u2 start_pc = cj_ru2(ptr + offset);
                        u2 length = cj_ru2(ptr + offset + 2);
                        u2 name_index = cj_ru2(ptr + offset + 4);
                        u2 descriptor_index = cj_ru2(ptr + offset + 6);
                        u2 index = cj_ru2(ptr + offset + 8);

                        var->start_pc = start_pc;
                        var->length = length;
                        var->name_index = name_index;
                        var->descriptor_index = descriptor_index;
                        var->index = index;

                        vars[j] = var;
                        offset += 10;
                    }
                }

                tab->local_vars = vars;
                tab->length = len;
                code->local_var_tab = tab;

                break;
            }
        }

    }

    return code->local_var_tab;
}

cj_local_var_type_tab_t *cj_code_get_local_var_type_table(cj_code_t *code) {
    CODE_COMMON_CHECK(code);

    if (code->local_var_type_tab == NULL) {
        /**
         * LocalVariableTypeTable_attribute {
         *      u2 attribute_name_index;
         *      u4 attribute_length;
         *      u2 local_variable_type_table_length;
         *      {   u2 start_pc;
         *          u2 length;
         *          u2 name_index;
         *          u2 signature_index;
         *          u2 index;
         *      } local_variable_type_table[local_variable_type_table_length];
         *  }
         *
         */

        buf_ptr ptr = cj_class_get_buf_ptr(code->method->klass, 0);
        for (int i = 0; i < code->attr_group->count; ++i) {
            cj_attribute_t *attr = cj_attribute_group_get(code->method->klass, code->attr_group, i);
            if (attr->type == CJ_ATTR_LocalVariableTypeTable) {
                u4 offset = cj_attribute_get_head_offset(attr) + 6;
                u2 len = cj_ru2(ptr + offset);
                offset += 2;

                cj_local_var_type_tab_t *tab = malloc(sizeof(cj_local_var_type_tab_t));
                cj_local_var_type_t **vars = NULL;
                if (len > 0) {
                    vars = malloc(sizeof(cj_local_var_type_t *) * len);
                    for (int j = 0; j < len; ++j) {
                        cj_local_var_type_t *var = malloc(sizeof(cj_local_var_type_t));
                        u2 start_pc = cj_ru2(ptr + offset);
                        u2 length = cj_ru2(ptr + offset + 2);
                        u2 name_index = cj_ru2(ptr + offset + 4);
                        u2 signature_index = cj_ru2(ptr + offset + 6);
                        u2 index = cj_ru2(ptr + offset + 8);

                        var->start_pc = start_pc;
                        var->length = length;
                        var->name_index = name_index;
                        var->signature_index = signature_index;
                        var->index = index;

                        vars[j] = var;
                        offset += 10;
                    }
                }

                tab->types = vars;
                tab->length = len;
                code->local_var_type_tab = tab;

                break;
            }
        }

    }

    return code->local_var_type_tab;
}


void cj_code_verification_type_info(buf_ptr ptr, u4 *offset) {

    /*
    union verification_type_info {
        Top_variable_info;
        Integer_variable_info;
        Float_variable_info;
        Long_variable_info;
        Double_variable_info;
        Null_variable_info;
        UninitializedThis_variable_info;
        Object_variable_info;
        Uninitialized_variable_info;
    }
     */

    u1 tag = cj_ru1(ptr);
    switch (tag) {

        case 0:
            //ITEM_Top
            break;
        case 1:
            //ITEM_Integer
            break;
        case 2:
            //ITEM_Float
            break;
        case 3:
            //ITEM_Double
            break;
        case 4:
            //ITEM_Long
            break;
        case 5:
            //ITEM_Null
            break;
        case 6: {
            //ITEM_UninitializedThis
            //u2 offset;
            *offset += 2;
            break;
        }
        case 7: {
            //ITEM_Object
            //u2 cpool_index ;
            *offset += 2;
            break;
        }
        case 8:
            //ITEM_Uninitialized
            break;
        default:
            fprintf(stderr, "Error: invalid verification type info %d\n", tag);
            break;
    }

    *offset += 1;
}


cj_stack_map_tab_t *cj_code_get_stack_map_table(cj_code_t *code) {
    CODE_COMMON_CHECK(code);

    if (code->stack_map_tab == NULL) {

        /**
         *
         * union stack_map_frame {
         *    same_frame;
         *    same_locals_1_stack_item_frame;
         *    same_locals_1_stack_item_frame_extended;
         *    chop_frame;
         *    same_frame_extended;
         *    append_frame;
         *    full_frame;
         *  }
         *
         */

        buf_ptr ptr = cj_class_get_buf_ptr(code->method->klass, 0);
        for (int i = 0; i < code->attr_group->count; ++i) {
            cj_attribute_t *attr = cj_attribute_group_get(code->method->klass, code->attr_group, i);
            if (attr->type == CJ_ATTR_StackMapTable) {
                u4 offset = cj_attribute_get_head_offset(attr) + 6;
                u2 len = cj_ru2(ptr + offset);
                offset += 2;

                cj_stack_map_tab_t *tab = malloc(sizeof(cj_stack_map_tab_t));
                tab->length = len;

                if (len > 0) {
                    cj_stack_map_frame_t **frames = malloc(sizeof(cj_stack_map_frame_t *) * len);
                    for (int j = 0; j < len; ++j) {
                        cj_stack_map_frame_t *frame = malloc(sizeof(cj_stack_map_frame_t));
                        u1 type = cj_ru1(ptr + offset);
                        ++offset;
                        // u1 frame_type = SAME; /* 0-63 */
                        frame->type = type;
                        if (type < 64) {
                            frame->frame_type = CJ_SMFT_SAME;
                        } else if (type < 128) {
                            frame->frame_type = CJ_SMFT_SAME_LOCALS_1_STACK_ITEM;
                            u4 ofst = 0;
                            cj_code_verification_type_info(ptr + offset, &ofst);
                            offset += ofst;
                        } else if (type == 247) {
                            frame->frame_type = CJ_SMFT_SAME_LOCALS_1_STACK_ITEM_EXTENDED;
                            u2 offset_delta = cj_ru2(ptr + offset);
                            offset += 2;

                            frame->offset_delta = offset_delta;

                            u4 ofst = 0;
                            cj_code_verification_type_info(ptr + offset, &ofst);
                            offset += ofst;

                        } else if (type >= 248 && type <= 250) {
                            frame->frame_type = CJ_SMFT_CHOP;
                            u2 offset_delta = cj_ru2(ptr + offset);
                            offset += 2;

                            frame->offset_delta = offset_delta;

                        } else if (type == 251) {
                            frame->frame_type = CJ_SMFT_SAME_FRAME_EXTENDED;
                            u2 offset_delta = cj_ru2(ptr + offset);
                            offset += 2;

                            frame->offset_delta = offset_delta;
                        } else if (type >= 252 && type <= 254) {
                            frame->frame_type = CJ_SMFT_APPEND;
                            u2 offset_delta = cj_ru2(ptr + offset);
                            offset += 2;

                            frame->offset_delta = offset_delta;

                            int vel = type - 251;
                            for (int k = 0; k < vel; ++k) {
                                u4 ofst = 0;
                                cj_code_verification_type_info(ptr + offset, &ofst);
                                offset += ofst;
                            }

                        } else if (type == 255) {
                            frame->frame_type = CJ_SMFT_FULL_FRAME;

                            u2 offset_delta = cj_ru2(ptr + offset);
                            u2 number_of_locals = cj_ru2(ptr + offset + 2);
                            offset += 4;

                            frame->offset_delta = offset_delta;

                            for (int k = 0; k < number_of_locals; ++k) {
                                u4 ofst = 0;
                                cj_code_verification_type_info(ptr + offset, &ofst);
                                offset += ofst;
                            }


                            u2 number_of_stack_items = cj_ru2(ptr + offset);
                            offset += 2;
                            for (int k = 0; k < number_of_stack_items; ++k) {
                                u4 ofst = 0;
                                cj_code_verification_type_info(ptr + offset, &ofst);
                                offset += ofst;
                            }


                        } else {
                            fprintf(stderr, "Error: invalid stack map frame tag %d\n", type);
                        }

                        frames[j] = frame;
                    }
                    tab->frames = frames;
                } else {
                    tab->frames = NULL;
                }

                code->stack_map_tab = tab;
                break;
            }
        }

    }

    return code->stack_map_tab;
}
