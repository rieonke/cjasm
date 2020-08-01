//
// Created by Rieon Ke on 2020/8/1.
//

#include "def.h"
#include "code.h"
#include "attribute.h"
#include "method.h"
#include "class.h"
#include "util.h"

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

    cj_sfree(code);
}
