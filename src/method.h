//
// Created by Rieon Ke on 2020/7/24.
//

#ifndef CJASM_METHOD_H
#define CJASM_METHOD_H

#include "util.h"

CJ_INTERNAL cj_method_t *cj_method_group_get(cj_class_t *ctx, cj_method_group_t *set, u2 idx);

CJ_INTERNAL void cj_method_group_free(cj_method_group_t *set);

CJ_INTERNAL void cj_method_free(cj_method_t *method);

CJ_INTERNAL void cj_code_iterate(cj_code_t *code, void(*callback)(cj_insn_t *, void *ctx), void *ctx);

CJ_INTERNAL cj_code_iter_t cj_code_iter_start(cj_code_t *code);

CJ_INTERNAL bool cj_code_iter_has_next(cj_code_iter_t *iter);

CJ_INTERNAL cj_insn_t *cj_code_iter_next(cj_code_iter_t *iter);

CJ_INTERNAL void cj_insn_free(cj_insn_t *insn);

CJ_INTERNAL u2 cj_code_compute_max_stack(cj_code_t *code);

CJ_INTERNAL void cj_print_opcode(enum cj_opcode code);

#endif //CJASM_METHOD_H
