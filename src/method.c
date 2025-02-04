//
// Created by Rieon Ke on 2020/7/19.
//
#include <assert.h>
#include <stdio.h>
#include "def.h"
#include "class.h"
#include "descriptor.h"
#include "cpool.h"
#include "util.h"
#include "annotation.h"
#include "method.h"
#include "attribute.h"
#include "mem_buf.h"
#include "code.h"

#define priv(m) ((cj_method_priv_t*)(m->priv))

typedef struct cj_method_priv_s cj_method_priv_t;
struct cj_method_priv_s {
    u4 dirty;
    u4 head;
    u4 tail;
    u2 name_index;
    u2 desc_index;
    bool annotation_set_initialized;
    cj_annotation_group_t *annotation_group;
    cj_attribute_group_t *attribute_group;
    cj_code_t *code;
    cj_descriptor_t *descriptor;
};

CJ_INTERNAL void cj_print_opcode(enum cj_opcode code) {

    switch (code) {

        case OP_NOP:
            printf("nop\n");
            break;
        case OP_ACONST_NULL:
            printf("aconst_null\n");
            break;
        case OP_ICONST_M1:
            printf("iconst_m1\n");
            break;
        case OP_ICONST_0:
            printf("iconst_0\n");
            break;
        case OP_ICONST_1:
            printf("iconst_1\n");
            break;
        case OP_ICONST_2:
            printf("iconst_2\n");
            break;
        case OP_ICONST_3:
            printf("iconst_3\n");
            break;
        case OP_ICONST_4:
            printf("iconst_4\n");
            break;
        case OP_ICONST_5:
            printf("iconst_5\n");
            break;
        case OP_LCONST_0:
            printf("lconst_0\n");
            break;
        case OP_LCONST_1:
            printf("lconst_1\n");
            break;
        case OP_FCONST_0:
            printf("fconst_0\n");
            break;
        case OP_FCONST_1:
            printf("fconst_1\n");
            break;
        case OP_FCONST_2:
            printf("fconst_2\n");
            break;
        case OP_DCONST_0:
            printf("dconst_0\n");
            break;
        case OP_DCONST_1:
            printf("dconst_1\n");
            break;
        case OP_BIPUSH:
            printf("bipush\n");
            break;
        case OP_SIPUSH:
            printf("sipush\n");
            break;
        case OP_LDC:
            printf("ldc\n");
            break;
        case OP_LDC_W:
            printf("ldc_w\n");
            break;
        case OP_LDC2_W:
            printf("ldc2_w\n");
            break;
        case OP_ILOAD:
            printf("iload\n");
            break;
        case OP_LLOAD:
            printf("lload\n");
            break;
        case OP_FLOAD:
            printf("fload\n");
            break;
        case OP_DLOAD:
            printf("dload\n");
            break;
        case OP_ALOAD:
            printf("aload\n");
            break;
        case OP_ILOAD_0:
            printf("iload_0\n");
            break;
        case OP_ILOAD_1:
            printf("iload_1\n");
            break;
        case OP_ILOAD_2:
            printf("iload_2\n");
            break;
        case OP_ILOAD_3:
            printf("iload_3\n");
            break;
        case OP_LLOAD_0:
            printf("lload_0\n");
            break;
        case OP_LLOAD_1:
            printf("lload_1\n");
            break;
        case OP_LLOAD_2:
            printf("lload_2\n");
            break;
        case OP_LLOAD_3:
            printf("lload_3\n");
            break;
        case OP_FLOAD_0:
            printf("fload_0\n");
            break;
        case OP_FLOAD_1:
            printf("fload_1\n");
            break;
        case OP_FLOAD_2:
            printf("fload_2\n");
            break;
        case OP_FLOAD_3:
            printf("fload_3\n");
            break;
        case OP_DLOAD_0:
            printf("dload_0\n");
            break;
        case OP_DLOAD_1:
            printf("dload_1\n");
            break;
        case OP_DLOAD_2:
            printf("dload_2\n");
            break;
        case OP_DLOAD_3:
            printf("dload_3\n");
            break;
        case OP_ALOAD_0:
            printf("aload_0\n");
            break;
        case OP_ALOAD_1:
            printf("aload_1\n");
            break;
        case OP_ALOAD_2:
            printf("aload_2\n");
            break;
        case OP_ALOAD_3:
            printf("aload_3\n");
            break;
        case OP_IALOAD:
            printf("iaload\n");
            break;
        case OP_LALOAD:
            printf("laload\n");
            break;
        case OP_FALOAD:
            printf("faload\n");
            break;
        case OP_DALOAD:
            printf("daload\n");
            break;
        case OP_AALOAD:
            printf("aaload\n");
            break;
        case OP_BALOAD:
            printf("baload\n");
            break;
        case OP_CALOAD:
            printf("caload\n");
            break;
        case OP_SALOAD:
            printf("saload\n");
            break;
        case OP_ISTORE:
            printf("istore\n");
            break;
        case OP_LSTORE:
            printf("lstore\n");
            break;
        case OP_FSTORE:
            printf("fstore\n");
            break;
        case OP_DSTORE:
            printf("dstore\n");
            break;
        case OP_ASTORE:
            printf("astore\n");
            break;
        case OP_ISTORE_0:
            printf("istore_0\n");
            break;
        case OP_ISTORE_1:
            printf("istore_1\n");
            break;
        case OP_ISTORE_2:
            printf("istore_2\n");
            break;
        case OP_ISTORE_3:
            printf("istore_3\n");
            break;
        case OP_LSTORE_0:
            printf("lstore_0\n");
            break;
        case OP_LSTORE_1:
            printf("lstore_1\n");
            break;
        case OP_LSTORE_2:
            printf("lstore_2\n");
            break;
        case OP_LSTORE_3:
            printf("lstore_3\n");
            break;
        case OP_FSTORE_0:
            printf("fstore_0\n");
            break;
        case OP_FSTORE_1:
            printf("fstore_1\n");
            break;
        case OP_FSTORE_2:
            printf("fstore_2\n");
            break;
        case OP_FSTORE_3:
            printf("fstore_3\n");
            break;
        case OP_DSTORE_0:
            printf("dstore_0\n");
            break;
        case OP_DSTORE_1:
            printf("dstore_1\n");
            break;
        case OP_DSTORE_2:
            printf("dstore_2\n");
            break;
        case OP_DSTORE_3:
            printf("dstore_3\n");
            break;
        case OP_ASTORE_0:
            printf("astore_0\n");
            break;
        case OP_ASTORE_1:
            printf("astore_1\n");
            break;
        case OP_ASTORE_2:
            printf("astore_2\n");
            break;
        case OP_ASTORE_3:
            printf("astore_3\n");
            break;
        case OP_IASTORE:
            printf("iastore\n");
            break;
        case OP_LASTORE:
            printf("lastore\n");
            break;
        case OP_FASTORE:
            printf("fastore\n");
            break;
        case OP_DASTORE:
            printf("dastore\n");
            break;
        case OP_AASTORE:
            printf("aastore\n");
            break;
        case OP_BASTORE:
            printf("bastore\n");
            break;
        case OP_CASTORE:
            printf("castore\n");
            break;
        case OP_SASTORE:
            printf("sastore\n");
            break;
        case OP_POP:
            printf("pop\n");
            break;
        case OP_POP2:
            printf("pop2\n");
            break;
        case OP_DUP:
            printf("dup\n");
            break;
        case OP_DUP_X1:
            printf("dup_x1\n");
            break;
        case OP_DUP_X2:
            printf("dup_x2\n");
            break;
        case OP_DUP2:
            printf("dup2\n");
            break;
        case OP_DUP2_X1:
            printf("dup2_x1\n");
            break;
        case OP_DUP2_X2:
            printf("dup2_x2\n");
            break;
        case OP_SWAP:
            printf("swap\n");
            break;
        case OP_IADD:
            printf("iadd\n");
            break;
        case OP_LADD:
            printf("ladd\n");
            break;
        case OP_FADD:
            printf("fadd\n");
            break;
        case OP_DADD:
            printf("dadd\n");
            break;
        case OP_ISUB:
            printf("isub\n");
            break;
        case OP_LSUB:
            printf("lsub\n");
            break;
        case OP_FSUB:
            printf("fsub\n");
            break;
        case OP_DSUB:
            printf("dsub\n");
            break;
        case OP_IMUL:
            printf("imul\n");
            break;
        case OP_LMUL:
            printf("lmul\n");
            break;
        case OP_FMUL:
            printf("fmul\n");
            break;
        case OP_DMUL:
            printf("dmul\n");
            break;
        case OP_IDIV:
            printf("idiv\n");
            break;
        case OP_LDIV:
            printf("ldiv\n");
            break;
        case OP_FDIV:
            printf("fdiv\n");
            break;
        case OP_DDIV:
            printf("ddiv\n");
            break;
        case OP_IREM:
            printf("irem\n");
            break;
        case OP_LREM:
            printf("lrem\n");
            break;
        case OP_FREM:
            printf("frem\n");
            break;
        case OP_DREM:
            printf("drem\n");
            break;
        case OP_INEG:
            printf("ineg\n");
            break;
        case OP_LNEG:
            printf("lneg\n");
            break;
        case OP_FNEG:
            printf("fneg\n");
            break;
        case OP_DNEG:
            printf("dneg\n");
            break;
        case OP_ISHL:
            printf("ishl\n");
            break;
        case OP_LSHL:
            printf("lshl\n");
            break;
        case OP_ISHR:
            printf("ishr\n");
            break;
        case OP_LSHR:
            printf("lshr\n");
            break;
        case OP_IUSHR:
            printf("iushr\n");
            break;
        case OP_LUSHR:
            printf("lushr\n");
            break;
        case OP_IAND:
            printf("iand\n");
            break;
        case OP_LAND:
            printf("land\n");
            break;
        case OP_IOR:
            printf("ior\n");
            break;
        case OP_LOR:
            printf("lor\n");
            break;
        case OP_IXOR:
            printf("ixor\n");
            break;
        case OP_LXOR:
            printf("lxor\n");
            break;
        case OP_IINC:
            printf("iinc\n");
            break;
        case OP_I2L:
            printf("i2l\n");
            break;
        case OP_I2F:
            printf("i2f\n");
            break;
        case OP_I2D:
            printf("i2d\n");
            break;
        case OP_L2I:
            printf("l2i\n");
            break;
        case OP_L2F:
            printf("l2f\n");
            break;
        case OP_L2D:
            printf("l2d\n");
            break;
        case OP_F2I:
            printf("f2i\n");
            break;
        case OP_F2L:
            printf("f2l\n");
            break;
        case OP_F2D:
            printf("f2d\n");
            break;
        case OP_D2I:
            printf("d2i\n");
            break;
        case OP_D2L:
            printf("d2l\n");
            break;
        case OP_D2F:
            printf("d2f\n");
            break;
        case OP_I2B:
            printf("i2b\n");
            break;
        case OP_I2C:
            printf("i2c\n");
            break;
        case OP_I2S:
            printf("i2s\n");
            break;
        case OP_LCMP:
            printf("lcmp\n");
            break;
        case OP_FCMPL:
            printf("fcmpl\n");
            break;
        case OP_FCMPG:
            printf("fcmpg\n");
            break;
        case OP_DCMPL:
            printf("dcmpl\n");
            break;
        case OP_DCMPG:
            printf("dcmpg\n");
            break;
        case OP_IFEQ:
            printf("ifeq\n");
            break;
        case OP_IFNE:
            printf("ifne\n");
            break;
        case OP_IFLT:
            printf("iflt\n");
            break;
        case OP_IFGE:
            printf("ifge\n");
            break;
        case OP_IFGT:
            printf("ifgt\n");
            break;
        case OP_IFLE:
            printf("ifle\n");
            break;
        case OP_IF_ICMPEQ:
            printf("if_icmpeq\n");
            break;
        case OP_IF_ICMPNE:
            printf("if_icmpne\n");
            break;
        case OP_IF_ICMPLT:
            printf("if_icmplt\n");
            break;
        case OP_IF_ICMPGE:
            printf("if_icmpge\n");
            break;
        case OP_IF_ICMPGT:
            printf("if_icmpgt\n");
            break;
        case OP_IF_ICMPLE:
            printf("if_icmple\n");
            break;
        case OP_IF_ACMPEQ:
            printf("if_acmpeq\n");
            break;
        case OP_IF_ACMPNE:
            printf("if_acmpne\n");
            break;
        case OP_GETSTATIC:
            printf("getstatic\n");
            break;
        case OP_PUTSTATIC:
            printf("putstatic\n");
            break;
        case OP_GETFIELD:
            printf("getfield\n");
            break;
        case OP_PUTFIELD:
            printf("putfield\n");
            break;
        case OP_INVOKEVIRTUAL:
            printf("invokevirtual\n");
            break;
        case OP_INVOKESPECIAL:
            printf("invokespecial\n");
            break;
        case OP_INVOKESTATIC:
            printf("invokestatic\n");
            break;
        case OP_INVOKEINTERFACE:
            printf("invokeinterface\n");
            break;
        case OP_INVOKEDYNAMIC:
            printf("invokedynamic\n");
            break;
        case OP_NEW:
            printf("new\n");
            break;
        case OP_NEWARRAY:
            printf("newarray\n");
            break;
        case OP_ANEWARRAY:
            printf("anewarray\n");
            break;
        case OP_ARRAYLENGTH:
            printf("arraylength\n");
            break;
        case OP_ATHROW:
            printf("athrow\n");
            break;
        case OP_CHECKCAST:
            printf("checkcast\n");
            break;
        case OP_INSTANCEOF:
            printf("instanceof\n");
            break;
        case OP_MONITORENTER:
            printf("monitorenter\n");
            break;
        case OP_MONITOREXIT:
            printf("monitorexit\n");
            break;
        case OP_GOTO:
            printf("goto\n");
            break;
        case OP_JSR:
            printf("jsr\n");
            break;
        case OP_RET:
            printf("ret\n");
            break;
        case OP_TABLESWITCH:
            printf("tableswitch\n");
            break;
        case OP_LOOKUPSWITCH:
            printf("lookupswitch\n");
            break;
        case OP_IRETURN:
            printf("ireturn\n");
            break;
        case OP_LRETURN:
            printf("lreturn\n");
            break;
        case OP_FRETURN:
            printf("freturn\n");
            break;
        case OP_DRETURN:
            printf("dreturn\n");
            break;
        case OP_ARETURN:
            printf("areturn\n");
            break;
        case OP_RETURN:
            printf("return\n");
            break;
        case OP_WIDE:
            printf("wide\n");
            break;
        case OP_MULTIANEWARRAY:
            printf("multianewarray\n");
            break;
        case OP_IFNULL:
            printf("ifnull\n");
            break;
        case OP_IFNONNULL:
            printf("ifnonnull\n");
            break;
        case OP_GOTO_W:
            printf("goto_w\n");
            break;
        case OP_JSR_W:
            printf("jsr_w\n");
            break;
        case OP_BREAKPOINT:
            printf("breakpoint\n");
            break;
        case OP_IMPDEP1:
            printf("impdep1\n");
            break;
        case OP_IMPDEP2:
            printf("impdep2\n");
            break;
    }


}


CJ_INTERNAL void cj_code_iterate(cj_code_t *code, void(*callback)(cj_insn_t *, void *ctx), void *ctx) {

    cj_code_iter_t iter = cj_code_iter_start(code);
    while (cj_code_iter_has_next(&iter)) {
        cj_insn_t *insn = cj_code_iter_next(&iter);
        if (callback != NULL)
            callback(insn, ctx);
        cj_insn_free(insn);
    }

}

CJ_INTERNAL cj_code_iter_t cj_code_iter_start(cj_code_t *code) {

    cj_code_iter_t iter = {
            code, 0, code->length
    };

    return iter;
}

CJ_INTERNAL bool cj_code_iter_has_next(cj_code_iter_t *iter) {
    return iter->current < iter->length;
}

CJ_INTERNAL cj_insn_t *cj_code_iter_next(cj_code_iter_t *iter) {

    cj_code_t *code = iter->code;
    cj_class_t *ctx = code->method->klass;
    u4 offset = code->head;

    buf_ptr ptr = cj_class_get_buf_ptr(ctx, offset);

    u4 len = iter->current;

    enum cj_opcode opcode = (enum cj_opcode) cj_ru1(ptr + len);

    cj_insn_t *insn = malloc(sizeof(cj_insn_t));
    insn->opcode = opcode;
    insn->mark = len;

    switch (opcode) {

        case OP_NOP:
        case OP_ACONST_NULL:
        case OP_ICONST_M1:
        case OP_ICONST_0:
        case OP_ICONST_1:
        case OP_ICONST_2:
        case OP_ICONST_3:
        case OP_ICONST_4:
        case OP_ICONST_5:
        case OP_LCONST_0:
        case OP_LCONST_1:
        case OP_FCONST_0:
        case OP_FCONST_1:
        case OP_FCONST_2:
        case OP_DCONST_0:
        case OP_DCONST_1:
        case OP_IALOAD:
        case OP_LALOAD:
        case OP_FALOAD:
        case OP_DALOAD:
        case OP_AALOAD:
        case OP_BALOAD:
        case OP_CALOAD:
        case OP_SALOAD:
        case OP_IASTORE:
        case OP_LASTORE:
        case OP_FASTORE:
        case OP_DASTORE:
        case OP_AASTORE:
        case OP_BASTORE:
        case OP_CASTORE:
        case OP_SASTORE:
        case OP_POP:
        case OP_POP2:
        case OP_DUP:
        case OP_DUP_X1:
        case OP_DUP_X2:
        case OP_DUP2:
        case OP_DUP2_X1:
        case OP_DUP2_X2:
        case OP_SWAP:
        case OP_IADD:
        case OP_LADD:
        case OP_FADD:
        case OP_DADD:
        case OP_ISUB:
        case OP_LSUB:
        case OP_FSUB:
        case OP_DSUB:
        case OP_IMUL:
        case OP_LMUL:
        case OP_FMUL:
        case OP_DMUL:
        case OP_IDIV:
        case OP_LDIV:
        case OP_FDIV:
        case OP_DDIV:
        case OP_IREM:
        case OP_LREM:
        case OP_FREM:
        case OP_DREM:
        case OP_INEG:
        case OP_LNEG:
        case OP_FNEG:
        case OP_DNEG:
        case OP_ISHL:
        case OP_LSHL:
        case OP_ISHR:
        case OP_LSHR:
        case OP_IUSHR:
        case OP_LUSHR:
        case OP_IAND:
        case OP_LAND:
        case OP_IOR:
        case OP_LOR:
        case OP_IXOR:
        case OP_LXOR:
        case OP_I2L:
        case OP_I2F:
        case OP_I2D:
        case OP_L2I:
        case OP_L2F:
        case OP_L2D:
        case OP_F2I:
        case OP_F2L:
        case OP_F2D:
        case OP_D2I:
        case OP_D2L:
        case OP_D2F:
        case OP_I2B:
        case OP_I2C:
        case OP_I2S:
        case OP_LCMP:
        case OP_FCMPL:
        case OP_FCMPG:
        case OP_DCMPL:
        case OP_DCMPG:
        case OP_IRETURN:
        case OP_LRETURN:
        case OP_FRETURN:
        case OP_DRETURN:
        case OP_ARETURN:
        case OP_RETURN:
        case OP_ARRAYLENGTH:
        case OP_ATHROW:
        case OP_MONITORENTER:
        case OP_MONITOREXIT:
        case OP_BREAKPOINT:
        case OP_IMPDEP1:
        case OP_IMPDEP2: {
            insn->type = INSN;
            insn->opcode = opcode;
            len++;
            break;
        }
        case OP_ILOAD_0:
        case OP_ILOAD_1:
        case OP_ILOAD_2:
        case OP_ILOAD_3:
        case OP_LLOAD_0:
        case OP_LLOAD_1:
        case OP_LLOAD_2:
        case OP_LLOAD_3:
        case OP_FLOAD_0:
        case OP_FLOAD_1:
        case OP_FLOAD_2:
        case OP_FLOAD_3:
        case OP_DLOAD_0:
        case OP_DLOAD_1:
        case OP_DLOAD_2:
        case OP_DLOAD_3:
        case OP_ALOAD_0:
        case OP_ALOAD_1:
        case OP_ALOAD_2:
        case OP_ALOAD_3: {

            opcode -= OP_ILOAD_0;

            insn->type = VAR;
            insn->var = opcode & 0x3;
            insn->opcode = OP_ILOAD + (opcode >> 2);

            len++;
            break;
        }
        case OP_ISTORE_0:
        case OP_ISTORE_1:
        case OP_ISTORE_2:
        case OP_ISTORE_3:
        case OP_LSTORE_0:
        case OP_LSTORE_1:
        case OP_LSTORE_2:
        case OP_LSTORE_3:
        case OP_FSTORE_0:
        case OP_FSTORE_1:
        case OP_FSTORE_2:
        case OP_FSTORE_3:
        case OP_DSTORE_0:
        case OP_DSTORE_1:
        case OP_DSTORE_2:
        case OP_DSTORE_3:
        case OP_ASTORE_0:
        case OP_ASTORE_1:
        case OP_ASTORE_2:
        case OP_ASTORE_3: {

            opcode -= OP_ISTORE_0;

            insn->type = VAR;
            insn->var = opcode & 0x3;
            insn->opcode = OP_ISTORE + (opcode >> 2);

            len += 1;
            break;
        }
        case OP_IFEQ:
        case OP_IFNE:
        case OP_IFLT:
        case OP_IFGE:
        case OP_IFGT:
        case OP_IFLE:
        case OP_IF_ICMPEQ:
        case OP_IF_ICMPNE:
        case OP_IF_ICMPLT:
        case OP_IF_ICMPGE:
        case OP_IF_ICMPGT:
        case OP_IF_ICMPLE:
        case OP_IF_ACMPEQ:
        case OP_IF_ACMPNE:
        case OP_GOTO:
        case OP_JSR:
        case OP_IFNULL:
        case OP_IFNONNULL: {

            u2 idx = cj_ru2(ptr + len + 1);

            insn->type = JUMP;
            insn->label = idx;
            insn->opcode = opcode;

            len += 3;
            break;
        }
        case OP_GOTO_W:
        case OP_JSR_W: {

            insn->type = JUMP;
            insn->label = cj_ru4(ptr + len + 1);
            insn->opcode = opcode;

            len += 5;
            break;
        }
        case OP_WIDE: {

            opcode = cj_ru1(ptr + len + 1); //read next opcode

            insn->opcode = opcode;

            if (opcode == OP_IINC) {

                insn->type = IINC;
                insn->var = cj_ru2(ptr + len + 2);
                insn->incr = cj_ri2(ptr + len + 4);

                len += 6;
            } else {

                insn->type = VAR;
                insn->var = cj_ru2(code + 2);

                len += 4;
            }
            break;
        }
        case OP_TABLESWITCH: {

            /*
             *
             * tableswitch
             *  <0-3 byte pad>
             *  default, low, high  32位有符号整数
             *  jump offsets...
             *
             *  tableswitch 是一个可变长指令
             *  紧接着指令之后的一个0-3字节的对齐，这样后面的default就是从4字节对齐的（从方法开始位置算起，也就是方法的第一个指令位置算起）
             *  在对齐字节之后跟着三个32位有符号整数，default，low 和 high
             *  之后则是一个32位有符号整数偏移量列表，个数为 high - low + 1
             *  low 必须小于或等于high，high - low + 1可以看做是一个基于0的跳转表
             *  每一个32位有符号整数可以通过  (byte1 << 24) | (byte2 << 16) | (byte3 << 8) | byte4 来构造
             *
             *  目标地址可以根据跳转表中的偏移地址计算，
             *  也就是说，他们可以根据default的值计算得到。
             *  目标地址必须是包含了这个tableswitch的方法中的一条指令的地址。
             */

            u2 current_offset = len; //记住当前tableswitch所在的偏移地址
            len += 4 - (len & 3); //跳过对齐字节数

            i4 v_default = cj_ri4(ptr + len) + current_offset;
            i4 v_low = cj_ri4(ptr + len + 4);
            i4 v_height = cj_ri4(ptr + len + 8);
            i4 v_count = v_height - v_low + 1;

            len += 12;

            insn->type = TABLE_SWITCH;
            insn->opcode = opcode;
            insn->s_default = v_default;
            insn->s_low = v_low;
            insn->s_high = v_height;

            if (v_count > 0)
                insn->s_labels = malloc(sizeof(i4) * v_count);

            for (i4 i = 0; i < v_count; ++i) {
                i4 e = cj_ri4(ptr + len) + current_offset;
                insn->s_labels[i] = e;
                len += 4;
            }

            break;
        }
        case OP_LOOKUPSWITCH: {
            u2 current_offset = len;
            len += 4 - (len & 3);

            i4 v_default = cj_ri4(ptr + len) + current_offset;
            i4 v_pairs = cj_ri4(ptr + len + 4);
            len += 8;


            insn->type = LOOKUP_SWITCH;
            insn->opcode = opcode;
            insn->s_default = v_default;
            insn->s_pairs = v_pairs;

            if (v_pairs > 0) {
                insn->s_labels = malloc(sizeof(i4) * v_pairs);
                insn->s_keys = malloc(sizeof(i4) * v_pairs);
            }

            for (i4 i = 0; i < v_pairs; ++i) {
                i4 k = cj_ri4(ptr + len);
                i4 v = cj_ri4(ptr + len + 4) + len;

                insn->s_keys[i] = k;
                insn->s_labels[i] = v;

                len += 8;
            }

            break;
        }
        case OP_ILOAD:
        case OP_LLOAD:
        case OP_FLOAD:
        case OP_DLOAD:
        case OP_ALOAD:
        case OP_ISTORE:
        case OP_LSTORE:
        case OP_FSTORE:
        case OP_DSTORE:
        case OP_ASTORE:
        case OP_RET: {

            insn->type = VAR;
            insn->var = cj_ru1(ptr + len + 1);
            insn->opcode = opcode;

            len += 2;
            break;
        }
        case OP_BIPUSH:
        case OP_NEWARRAY: {
            insn->type = INT;
            insn->opcode = opcode;
            insn->val = cj_ri1(ptr + len + 1);

            len += 2;
            break;
        }
        case OP_SIPUSH: {

            insn->type = INT;
            insn->opcode = opcode;
            insn->val = cj_ri2(ptr + len + 1);

            len += 3;
            break;
        }
        case OP_LDC: {

            insn->type = LDC;
            insn->opcode = opcode;
            insn->cp_idx = cj_ru1(ptr + len + 1);

            len += 2;
            break;
        }
        case OP_LDC_W:
        case OP_LDC2_W: {

            insn->type = LDC;
            insn->opcode = opcode;
            insn->cp_idx = cj_ru2(ptr + len + 1);

            //todo check cj_ru2(ptr + len + 2) or cj_ru2(ptr + len + 1);

            len += 3;
            break;
        }
        case OP_GETSTATIC:
        case OP_PUTSTATIC:
        case OP_GETFIELD:
        case OP_PUTFIELD:
        case OP_INVOKEVIRTUAL:
        case OP_INVOKESPECIAL:
        case OP_INVOKESTATIC:
        case OP_INVOKEINTERFACE: {

            insn->opcode = opcode;
            insn->cp_idx = cj_ru2(ptr + len + 1);

            if (opcode < OP_INVOKEVIRTUAL) {
                insn->type = FIELD;
            } else {
                insn->type = METHOD;
            }


            if (opcode == OP_INVOKEINTERFACE) {
                len += 5;
            } else {
                len += 3;
            }
            break;
        }
        case OP_INVOKEDYNAMIC: {

            insn->type = INVOKE_DYNAMIC;
            insn->opcode = opcode;
            insn->cp_idx = cj_ru2(ptr + len + 1);

            len += 5;

            break;
        }
        case OP_NEW:
        case OP_ANEWARRAY:
        case OP_CHECKCAST:
        case OP_INSTANCEOF: {

            insn->type = TYPE;
            insn->opcode = opcode;
            insn->cp_idx = cj_ru2(ptr + len + 1);

            len += 3;
            break;
        }
        case OP_IINC: {

            insn->type = IINC;
            insn->opcode = opcode;
            insn->var = cj_ru1(ptr + len + 1);
            insn->incr = cj_ri1(ptr + len + 2);

            len += 3;
            break;
        }
        case OP_MULTIANEWARRAY: {

            insn->type = MULTI_ANEWARRAY;
            insn->opcode = opcode;
            insn->cp_idx = cj_ru2(ptr + len + 1);
            insn->dimensions = cj_ru1(ptr + len + 3);

            len += 4;
            break;
        }
    }


    assert(insn->opcode != OP_NOP);
    iter->current = len;

    return insn;

}


CJ_INTERNAL void cj_insn_free(cj_insn_t *insn) {

    if (insn == NULL) return;

    if (insn->type == TABLE_SWITCH) {
        cj_sfree(insn->s_labels);
    } else if (insn->type == LOOKUP_SWITCH) {
        cj_sfree(insn->s_labels);
        cj_sfree(insn->s_keys);
    }

    cj_sfree(insn);

}

CJ_INTERNAL cj_method_t *cj_method_group_get(cj_class_t *ctx, cj_method_group_t *set, u2 idx) {

    if (set->fetched == NULL) {
        set->fetched = calloc(sizeof(cj_method_t *), ctx->method_count);
    }

    if (set->fetched[idx] == NULL) {
        u4 head = set->heads[idx];
        u4 tail = set->tails[idx];

        buf_ptr buf = cj_class_get_buf_ptr(ctx, head);
        u2 access_flags = cj_ru2(buf);
        u2 name_index = cj_ru2(buf + 2);
        u2 descriptor_index = cj_ru2(buf + 4);
        u2 attributes_count = cj_ru2(buf + 6);

        cj_method_t *method = malloc(sizeof(cj_method_t));
        method->access_flags = access_flags;
        method->name = cj_cp_get_str(ctx, name_index);
        method->descriptor = cj_cp_get_str(ctx, descriptor_index);
        method->klass = ctx;
        method->index = idx;
        method->attribute_count = attributes_count;
        method->priv = calloc(sizeof(cj_method_priv_t), 1);
        priv(method)->head = head;
        priv(method)->tail = tail;
        priv(method)->name_index = name_index;
        priv(method)->desc_index = descriptor_index;
        priv(method)->attribute_group = cj_class_get_method_attribute_group(ctx, idx);
        priv(method)->annotation_group = NULL;
        priv(method)->annotation_set_initialized = false;
        priv(method)->code = NULL;
        priv(method)->descriptor = NULL;

        set->fetched[idx] = method;
    }

    return set->fetched[idx];
}

CJ_INTERNAL void cj_method_group_free(cj_method_group_t *set) {
    if (set == NULL) return;
    cj_sfree(set->heads);
    cj_sfree(set->tails);
    if (set->fetched != NULL) {
        for (int i = 0; i < set->count; ++i) {
            cj_method_free(set->fetched[i]);
        }
    }
    cj_sfree(set->fetched);
    cj_sfree(set);
}

CJ_INTERNAL void cj_method_free(cj_method_t *method) {
    if (method == NULL) return;
    if (priv(method) != NULL && priv(method)->annotation_group != NULL) {
        cj_annotation_group_free(priv(method)->annotation_group);
    }

    //因为方法的attribute_set在class中被释放，所以在此处不再释放

    cj_code_free(priv(method)->code);

    if (priv(method)->descriptor != NULL) {
        cj_descriptor_free(priv(method)->descriptor);
    }

    cj_sfree(priv(method));
    cj_sfree(method);
}

const_str cj_method_get_name(cj_method_t *method) {
    return method->name;
}

u2 cj_method_get_access_flags(cj_method_t *method) {
    return method->access_flags;
}

u2 cj_method_get_attribute_count(cj_method_t *method) {

    return method->attribute_count;
}

cj_attribute_t *cj_method_get_attribute(cj_method_t *method, u2 idx) {
    if (method->klass == NULL ||
        method->attribute_count <= 0 ||
        priv(method)->attribute_group == NULL ||
        priv(method)->attribute_group->count <= idx) {
        return NULL;
    }

    return cj_attribute_group_get(method->klass, priv(method)->attribute_group, idx);
}

u2 cj_method_get_annotation_count(cj_method_t *method) {

    if (method == NULL ||
        priv(method) == NULL ||
        method->klass == NULL ||
        method->attribute_count <= 0) {
        return 0;
    }

    if (priv(method)->annotation_group == NULL && !priv(method)->annotation_set_initialized) {
        bool init = cj_annotation_group_init(method->klass, priv(method)->attribute_group,
                                             &priv(method)->annotation_group);
        priv(method)->annotation_set_initialized = init;
    }

    if (priv(method)->annotation_group == NULL) return 0;
    return priv(method)->annotation_group->count;
}

cj_annotation_t *cj_method_get_annotation(cj_method_t *method, u2 idx) {
    if (method == NULL ||
        priv(method) == NULL ||
        method->klass == NULL) {
        return NULL;
    }

    if (priv(method)->annotation_group == NULL && !priv(method)->annotation_set_initialized) {
        bool init = cj_annotation_group_init(method->klass, priv(method)->attribute_group,
                                             &priv(method)->annotation_group);
        priv(method)->annotation_set_initialized = init;
    }

    return cj_annotation_group_get(method->klass, priv(method)->annotation_group, idx);
}

cj_code_t *cj_method_get_code(cj_method_t *method) {

    if (method == NULL ||
        method->klass == NULL ||
        priv(method) == NULL) {
        return NULL;
    }
    if (priv(method)->code == NULL) {
        for (int i = 0; i < priv(method)->attribute_group->count; ++i) {
            cj_attribute_t *attr = cj_attribute_group_get(method->klass, priv(method)->attribute_group, i);
            if (attr->type == CJ_ATTR_Code) {
                priv(method)->code = cj_code_attr_parse(method, attr);
                break;
            }
        }
    }


    return priv(method)->code;
}

cj_descriptor_t *cj_method_get_descriptor(cj_method_t *method) {
    if (method == NULL || method->descriptor == NULL || priv(method) == NULL) return NULL;
    if (priv(method)->descriptor == NULL) {
        priv(method)->descriptor = cj_descriptor_parse(method->descriptor, strlen((char *) method->descriptor));
    }
    return priv(method)->descriptor;
}

cj_type_t *cj_method_get_return_type(cj_method_t *method) {
    cj_descriptor_t *descriptor = cj_method_get_descriptor(method);
    return descriptor->type;
}

u2 cj_method_get_parameter_count(cj_method_t *method) {
    cj_descriptor_t *descriptor = cj_method_get_descriptor(method);
    return descriptor->parameter_count;
}

bool cj_method_write_buf(cj_method_t *method, cj_mem_buf_t *buf) {
    if (method == NULL || method->klass == NULL || priv(method) == NULL) return false;

    if (priv(method)->dirty & CJ_DIRTY_REMOVE) {
        return false;
    }

    if (priv(method)->dirty == CJ_DIRTY_CLEAN) {

        cj_debug("untouched method: %s\n", method->name);
        u4 head = priv(method)->head;
        u4 tail = priv(method)->tail;
        if (head >= tail) {
            return false;
        }

        buf_ptr buf_ptr = cj_class_get_buf_ptr(method->klass, 0);

        cj_mem_buf_write_str(buf, (char *) buf_ptr + head, tail - head);
        return true;
    }

    /*
      method_info {
          u2             access_flags;
          u2             name_index;
          u2             descriptor_index;
          u2             attributes_count;
          attribute_info attributes[attributes_count];
      }
     */

    u2 name_idx = 0;
    u2 desc_idx = 0;
    cj_cp_put_str(method->klass, method->name, strlen((char *) method->name), &name_idx);
    cj_cp_put_str(method->klass, method->descriptor, strlen((char *) method->descriptor), &desc_idx);

    cj_mem_buf_write_u2(buf, method->access_flags);
    cj_mem_buf_write_u2(buf, name_idx);
    cj_mem_buf_write_u2(buf, desc_idx);

    if (priv(method)->attribute_group == NULL) {
        cj_mem_buf_write_u2(buf, /*attribute_count*/ 0);
    } else {
        bool attr_buf = cj_attribute_group_write_buf(method->klass, priv(method)->attribute_group, buf);
        assert(attr_buf == true); //todo error
    }

    return true;
}

cj_method_group_t *cj_method_group_new(u2 count, u4 *heads, u4 *tails) {
    if (count == 0 || heads == NULL || tails == NULL) return NULL;

    cj_method_group_t *group = NULL;

    group = malloc(sizeof(cj_method_group_t));
    group->index = 0;
    group->count = count;
    group->fetched = NULL;
    group->heads = heads;
    group->tails = tails;

    return group;
}

bool cj_method_group_write_buf(cj_class_t *cls, cj_method_group_t *group, cj_mem_buf_t *buf) {
    if (cls == NULL || group == NULL) return NULL;

    cj_mem_buf_pos_t *method_count_pos = cj_mem_buf_pos(buf);
    cj_mem_buf_write_u2(buf, 0);

    u2 count = 0;
    for (int i = 0; i < group->count; ++i) {
        cj_method_t *method = cj_method_group_get(cls, group, i);
        bool m_buf = cj_method_write_buf(method, buf);
        if (m_buf == false) continue;
        ++count;
    }

    if (count > 0)
        cj_mem_buf_pos_wu2(method_count_pos, count);
    return buf;
}

void cj_method_mark_dirty(cj_method_t *method, u4 flags) {
    if (method == NULL || priv(method) == NULL) return;
    priv(method)->dirty |= flags;
}

bool cj_method_rename(cj_method_t *method, unsigned char *name) {
    if (method == NULL || method->klass == NULL || priv(method) == NULL) return false;

    if (cj_streq(name, method->name)) return false;

    u2 idx = 0;
    method->name = cj_cp_put_str(method->klass, name, strlen((char *) name), &idx);
    cj_method_mark_dirty(method, CJ_DIRTY_NAME);

    //todo 如果我不想在其他的代码中替换当前的名字呢？比如duplicate & wrap 的情况？
    //替换所有当前类中的method_ref
    u2 nt_idx = cj_cp_find_name_and_type(method->klass, priv(method)->name_index, priv(method)->desc_index);

    priv(method)->name_index = idx;
    cj_cp_update_name_and_type(method->klass, nt_idx, priv(method)->name_index, priv(method)->desc_index);

    return true;
}

void cj_ann_group_init_or_create(cj_method_t *comp, bool visible) {

    if (!priv(comp)->annotation_set_initialized) {
        priv(comp)->annotation_set_initialized = cj_annotation_group_init(comp->klass, priv(comp)->attribute_group,
                                                                          &priv(comp)->annotation_group);
    }

    if (priv(comp)->attribute_group == NULL) { //create attribute_group
        cj_attribute_group_t *group = cj_attribute_group_new(0, NULL, NULL);
        priv(comp)->attribute_group = group;
    }

    if (priv(comp)->annotation_group == NULL) {
        cj_attribute_t *attribute = cj_attribute_new(
                visible ? CJ_ATTR_RuntimeVisibleAnnotations : CJ_ATTR_RuntimeInvisibleAnnotations);
        cj_annotation_group_t *ann_group = cj_annotation_group_create(0);
        cj_attribute_group_add(comp->klass, priv(comp)->attribute_group,
                               attribute); //todo 如果所加入的attr已经存在了，则获取现有的，impl cj_attribute_group_add_or_get
        if (visible) {
            ann_group->vi_attr = attribute;
        } else {
            ann_group->in_attr = attribute;
        }
    }


}

bool cj_method_add_annotation(cj_method_t *method, cj_annotation_t *annotation) {
    if (method == NULL || annotation == NULL || method->klass == NULL) return false;

    cj_annotation_group_init_or_create(method, annotation->visible);

    return cj_annotation_group_add(method->klass, priv(method)->annotation_group, annotation);
}


