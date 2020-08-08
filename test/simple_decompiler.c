//
// Created by Rieon Ke on 2020/7/16.
//
#include <string.h>
#include <stdio.h>
#include "../src/def.h"
#include "../src/util.h"
#include "../src/cpool.h"
#include "../src/class.h"
#include "../src/field.h"
#include "../src/descriptor.h"
#include "../src/method.h"
#include "../src/attribute.h"
#include "../src/annotation.h"
#include "../src/hashmap.h"
#include "../src/mem_buf.h"
#include "../src/code.h"

#define END printf("}\n");
//#define START_CLASS(cls) printf("class %s {\n", cls);

void print_insn(cj_mem_buf_t *buf, cj_insn_t *insn) {

    enum cj_opcode code = insn->opcode;

    cj_mem_buf_printf(buf, "%d: ", insn->mark)

    switch (code) {

        case OP_NOP: cj_mem_buf_printf(buf, "%s", "nop\n")
            break;
        case OP_ACONST_NULL: cj_mem_buf_printf(buf, "%s", "aconst_null\n")
            break;
        case OP_ICONST_M1: cj_mem_buf_printf(buf, "%s", "iconst_m1\n")
            break;
        case OP_ICONST_0: cj_mem_buf_printf(buf, "%s", "iconst_0\n")
            break;
        case OP_ICONST_1: cj_mem_buf_printf(buf, "%s", "iconst_1\n")
            break;
        case OP_ICONST_2: cj_mem_buf_printf(buf, "%s", "iconst_2\n")
            break;
        case OP_ICONST_3: cj_mem_buf_printf(buf, "%s", "iconst_3\n")
            break;
        case OP_ICONST_4: cj_mem_buf_printf(buf, "%s", "iconst_4\n")
            break;
        case OP_ICONST_5: cj_mem_buf_printf(buf, "%s", "iconst_5\n")
            break;
        case OP_LCONST_0: cj_mem_buf_printf(buf, "%s", "lconst_0\n")
            break;
        case OP_LCONST_1: cj_mem_buf_printf(buf, "%s", "lconst_1\n")
            break;
        case OP_FCONST_0: cj_mem_buf_printf(buf, "%s", "fconst_0\n")
            break;
        case OP_FCONST_1: cj_mem_buf_printf(buf, "%s", "fconst_1\n")
            break;
        case OP_FCONST_2: cj_mem_buf_printf(buf, "%s", "fconst_2\n")
            break;
        case OP_DCONST_0: cj_mem_buf_printf(buf, "%s", "dconst_0\n")
            break;
        case OP_DCONST_1: cj_mem_buf_printf(buf, "%s", "dconst_1\n")
            break;
        case OP_BIPUSH: cj_mem_buf_printf(buf, "%s %d\n", "bipush", insn->val)
            break;
        case OP_SIPUSH: cj_mem_buf_printf(buf, "%s %d\n", "sipush", insn->val)
            break;
        case OP_LDC: cj_mem_buf_printf(buf, "%s #%d\n", "ldc", insn->cp_idx)
            break;
        case OP_LDC_W: cj_mem_buf_printf(buf, "%s #%d\n", "ldc_w", insn->cp_idx)
            break;
        case OP_LDC2_W: cj_mem_buf_printf(buf, "%s #%d\n", "ldc2_w", insn->cp_idx)
            break;
        case OP_ILOAD: cj_mem_buf_printf(buf, "%s %d\n", "iload", insn->var)
            break;
        case OP_LLOAD: cj_mem_buf_printf(buf, "%s %d\n", "lload", insn->var)
            break;
        case OP_FLOAD: cj_mem_buf_printf(buf, "%s %d\n", "fload", insn->var)
            break;
        case OP_DLOAD: cj_mem_buf_printf(buf, "%s %d\n", "dload", insn->var)
            break;
        case OP_ALOAD: cj_mem_buf_printf(buf, "%s %d\n", "aload", insn->var)
            break;
        case OP_ILOAD_0: cj_mem_buf_printf(buf, "%s", "iload_0\n")
            break;
        case OP_ILOAD_1: cj_mem_buf_printf(buf, "%s", "iload_1\n")
            break;
        case OP_ILOAD_2: cj_mem_buf_printf(buf, "%s", "iload_2\n")
            break;
        case OP_ILOAD_3: cj_mem_buf_printf(buf, "%s", "iload_3\n")
            break;
        case OP_LLOAD_0: cj_mem_buf_printf(buf, "%s", "lload_0\n")
            break;
        case OP_LLOAD_1: cj_mem_buf_printf(buf, "%s", "lload_1\n")
            break;
        case OP_LLOAD_2: cj_mem_buf_printf(buf, "%s", "lload_2\n")
            break;
        case OP_LLOAD_3: cj_mem_buf_printf(buf, "%s", "lload_3\n")
            break;
        case OP_FLOAD_0: cj_mem_buf_printf(buf, "%s", "fload_0\n")
            break;
        case OP_FLOAD_1: cj_mem_buf_printf(buf, "%s", "fload_1\n")
            break;
        case OP_FLOAD_2: cj_mem_buf_printf(buf, "%s", "fload_2\n")
            break;
        case OP_FLOAD_3: cj_mem_buf_printf(buf, "%s", "fload_3\n")
            break;
        case OP_DLOAD_0: cj_mem_buf_printf(buf, "%s", "dload_0\n")
            break;
        case OP_DLOAD_1: cj_mem_buf_printf(buf, "%s", "dload_1\n")
            break;
        case OP_DLOAD_2: cj_mem_buf_printf(buf, "%s", "dload_2\n")
            break;
        case OP_DLOAD_3: cj_mem_buf_printf(buf, "%s", "dload_3\n")
            break;
        case OP_ALOAD_0: cj_mem_buf_printf(buf, "%s", "aload_0\n")
            break;
        case OP_ALOAD_1: cj_mem_buf_printf(buf, "%s", "aload_1\n")
            break;
        case OP_ALOAD_2: cj_mem_buf_printf(buf, "%s", "aload_2\n")
            break;
        case OP_ALOAD_3: cj_mem_buf_printf(buf, "%s", "aload_3\n")
            break;
        case OP_IALOAD: cj_mem_buf_printf(buf, "%s", "iaload\n")
            break;
        case OP_LALOAD: cj_mem_buf_printf(buf, "%s", "laload\n")
            break;
        case OP_FALOAD: cj_mem_buf_printf(buf, "%s", "faload\n")
            break;
        case OP_DALOAD: cj_mem_buf_printf(buf, "%s", "daload\n")
            break;
        case OP_AALOAD: cj_mem_buf_printf(buf, "%s", "aaload\n")
            break;
        case OP_BALOAD: cj_mem_buf_printf(buf, "%s", "baload\n")
            break;
        case OP_CALOAD: cj_mem_buf_printf(buf, "%s", "caload\n")
            break;
        case OP_SALOAD: cj_mem_buf_printf(buf, "%s", "saload\n")
            break;
        case OP_ISTORE: cj_mem_buf_printf(buf, "%s", "istore\n")
            break;
        case OP_LSTORE: cj_mem_buf_printf(buf, "%s", "lstore\n")
            break;
        case OP_FSTORE: cj_mem_buf_printf(buf, "%s", "fstore\n")
            break;
        case OP_DSTORE: cj_mem_buf_printf(buf, "%s", "dstore\n")
            break;
        case OP_ASTORE: cj_mem_buf_printf(buf, "%s", "astore\n")
            break;
        case OP_ISTORE_0: cj_mem_buf_printf(buf, "%s", "istore_0\n")
            break;
        case OP_ISTORE_1: cj_mem_buf_printf(buf, "%s", "istore_1\n")
            break;
        case OP_ISTORE_2: cj_mem_buf_printf(buf, "%s", "istore_2\n")
            break;
        case OP_ISTORE_3: cj_mem_buf_printf(buf, "%s", "istore_3\n")
            break;
        case OP_LSTORE_0: cj_mem_buf_printf(buf, "%s", "lstore_0\n")
            break;
        case OP_LSTORE_1: cj_mem_buf_printf(buf, "%s", "lstore_1\n")
            break;
        case OP_LSTORE_2: cj_mem_buf_printf(buf, "%s", "lstore_2\n")
            break;
        case OP_LSTORE_3: cj_mem_buf_printf(buf, "%s", "lstore_3\n")
            break;
        case OP_FSTORE_0: cj_mem_buf_printf(buf, "%s", "fstore_0\n")
            break;
        case OP_FSTORE_1: cj_mem_buf_printf(buf, "%s", "fstore_1\n")
            break;
        case OP_FSTORE_2: cj_mem_buf_printf(buf, "%s", "fstore_2\n")
            break;
        case OP_FSTORE_3: cj_mem_buf_printf(buf, "%s", "fstore_3\n")
            break;
        case OP_DSTORE_0: cj_mem_buf_printf(buf, "%s", "dstore_0\n")
            break;
        case OP_DSTORE_1: cj_mem_buf_printf(buf, "%s", "dstore_1\n")
            break;
        case OP_DSTORE_2: cj_mem_buf_printf(buf, "%s", "dstore_2\n")
            break;
        case OP_DSTORE_3: cj_mem_buf_printf(buf, "%s", "dstore_3\n")
            break;
        case OP_ASTORE_0: cj_mem_buf_printf(buf, "%s", "astore_0\n")
            break;
        case OP_ASTORE_1: cj_mem_buf_printf(buf, "%s", "astore_1\n")
            break;
        case OP_ASTORE_2: cj_mem_buf_printf(buf, "%s", "astore_2\n")
            break;
        case OP_ASTORE_3: cj_mem_buf_printf(buf, "%s", "astore_3\n")
            break;
        case OP_IASTORE: cj_mem_buf_printf(buf, "%s", "iastore\n")
            break;
        case OP_LASTORE: cj_mem_buf_printf(buf, "%s", "lastore\n")
            break;
        case OP_FASTORE: cj_mem_buf_printf(buf, "%s", "fastore\n")
            break;
        case OP_DASTORE: cj_mem_buf_printf(buf, "%s", "dastore\n")
            break;
        case OP_AASTORE: cj_mem_buf_printf(buf, "%s", "aastore\n")
            break;
        case OP_BASTORE: cj_mem_buf_printf(buf, "%s", "bastore\n")
            break;
        case OP_CASTORE: cj_mem_buf_printf(buf, "%s", "castore\n")
            break;
        case OP_SASTORE: cj_mem_buf_printf(buf, "%s", "sastore\n")
            break;
        case OP_POP: cj_mem_buf_printf(buf, "%s", "pop\n")
            break;
        case OP_POP2: cj_mem_buf_printf(buf, "%s", "pop2\n")
            break;
        case OP_DUP: cj_mem_buf_printf(buf, "%s", "dup\n")
            break;
        case OP_DUP_X1: cj_mem_buf_printf(buf, "%s", "dup_x1\n")
            break;
        case OP_DUP_X2: cj_mem_buf_printf(buf, "%s", "dup_x2\n")
            break;
        case OP_DUP2: cj_mem_buf_printf(buf, "%s", "dup2\n")
            break;
        case OP_DUP2_X1: cj_mem_buf_printf(buf, "%s", "dup2_x1\n")
            break;
        case OP_DUP2_X2: cj_mem_buf_printf(buf, "%s", "dup2_x2\n")
            break;
        case OP_SWAP: cj_mem_buf_printf(buf, "%s", "swap\n")
            break;
        case OP_IADD: cj_mem_buf_printf(buf, "%s", "iadd\n")
            break;
        case OP_LADD: cj_mem_buf_printf(buf, "%s", "ladd\n")
            break;
        case OP_FADD: cj_mem_buf_printf(buf, "%s", "fadd\n")
            break;
        case OP_DADD: cj_mem_buf_printf(buf, "%s", "dadd\n")
            break;
        case OP_ISUB: cj_mem_buf_printf(buf, "%s", "isub\n")
            break;
        case OP_LSUB: cj_mem_buf_printf(buf, "%s", "lsub\n")
            break;
        case OP_FSUB: cj_mem_buf_printf(buf, "%s", "fsub\n")
            break;
        case OP_DSUB: cj_mem_buf_printf(buf, "%s", "dsub\n")
            break;
        case OP_IMUL: cj_mem_buf_printf(buf, "%s", "imul\n")
            break;
        case OP_LMUL: cj_mem_buf_printf(buf, "%s", "lmul\n")
            break;
        case OP_FMUL: cj_mem_buf_printf(buf, "%s", "fmul\n")
            break;
        case OP_DMUL: cj_mem_buf_printf(buf, "%s", "dmul\n")
            break;
        case OP_IDIV: cj_mem_buf_printf(buf, "%s", "idiv\n")
            break;
        case OP_LDIV: cj_mem_buf_printf(buf, "%s", "ldiv\n")
            break;
        case OP_FDIV: cj_mem_buf_printf(buf, "%s", "fdiv\n")
            break;
        case OP_DDIV: cj_mem_buf_printf(buf, "%s", "ddiv\n")
            break;
        case OP_IREM: cj_mem_buf_printf(buf, "%s", "irem\n")
            break;
        case OP_LREM: cj_mem_buf_printf(buf, "%s", "lrem\n")
            break;
        case OP_FREM: cj_mem_buf_printf(buf, "%s", "frem\n")
            break;
        case OP_DREM: cj_mem_buf_printf(buf, "%s", "drem\n")
            break;
        case OP_INEG: cj_mem_buf_printf(buf, "%s", "ineg\n")
            break;
        case OP_LNEG: cj_mem_buf_printf(buf, "%s", "lneg\n")
            break;
        case OP_FNEG: cj_mem_buf_printf(buf, "%s", "fneg\n")
            break;
        case OP_DNEG: cj_mem_buf_printf(buf, "%s", "dneg\n")
            break;
        case OP_ISHL: cj_mem_buf_printf(buf, "%s", "ishl\n")
            break;
        case OP_LSHL: cj_mem_buf_printf(buf, "%s", "lshl\n")
            break;
        case OP_ISHR: cj_mem_buf_printf(buf, "%s", "ishr\n")
            break;
        case OP_LSHR: cj_mem_buf_printf(buf, "%s", "lshr\n")
            break;
        case OP_IUSHR: cj_mem_buf_printf(buf, "%s", "iushr\n")
            break;
        case OP_LUSHR: cj_mem_buf_printf(buf, "%s", "lushr\n")
            break;
        case OP_IAND: cj_mem_buf_printf(buf, "%s", "iand\n")
            break;
        case OP_LAND: cj_mem_buf_printf(buf, "%s", "land\n")
            break;
        case OP_IOR: cj_mem_buf_printf(buf, "%s", "ior\n")
            break;
        case OP_LOR: cj_mem_buf_printf(buf, "%s", "lor\n")
            break;
        case OP_IXOR: cj_mem_buf_printf(buf, "%s", "ixor\n")
            break;
        case OP_LXOR: cj_mem_buf_printf(buf, "%s", "lxor\n")
            break;
        case OP_IINC: cj_mem_buf_printf(buf, "%s", "iinc\n")
            break;
        case OP_I2L: cj_mem_buf_printf(buf, "%s", "i2l\n")
            break;
        case OP_I2F: cj_mem_buf_printf(buf, "%s", "i2f\n")
            break;
        case OP_I2D: cj_mem_buf_printf(buf, "%s", "i2d\n")
            break;
        case OP_L2I: cj_mem_buf_printf(buf, "%s", "l2i\n")
            break;
        case OP_L2F: cj_mem_buf_printf(buf, "%s", "l2f\n")
            break;
        case OP_L2D: cj_mem_buf_printf(buf, "%s", "l2d\n")
            break;
        case OP_F2I: cj_mem_buf_printf(buf, "%s", "f2i\n")
            break;
        case OP_F2L: cj_mem_buf_printf(buf, "%s", "f2l\n")
            break;
        case OP_F2D: cj_mem_buf_printf(buf, "%s", "f2d\n")
            break;
        case OP_D2I: cj_mem_buf_printf(buf, "%s", "d2i\n")
            break;
        case OP_D2L: cj_mem_buf_printf(buf, "%s", "d2l\n")
            break;
        case OP_D2F: cj_mem_buf_printf(buf, "%s", "d2f\n")
            break;
        case OP_I2B: cj_mem_buf_printf(buf, "%s", "i2b\n")
            break;
        case OP_I2C: cj_mem_buf_printf(buf, "%s", "i2c\n")
            break;
        case OP_I2S: cj_mem_buf_printf(buf, "%s", "i2s\n")
            break;
        case OP_LCMP: cj_mem_buf_printf(buf, "%s", "lcmp\n")
            break;
        case OP_FCMPL: cj_mem_buf_printf(buf, "%s", "fcmpl\n")
            break;
        case OP_FCMPG: cj_mem_buf_printf(buf, "%s", "fcmpg\n")
            break;
        case OP_DCMPL: cj_mem_buf_printf(buf, "%s", "dcmpl\n")
            break;
        case OP_DCMPG: cj_mem_buf_printf(buf, "%s", "dcmpg\n")
            break;
        case OP_IFEQ: cj_mem_buf_printf(buf, "%s %d\n", "ifeq", insn->label)
            break;
        case OP_IFNE: cj_mem_buf_printf(buf, "%s %d\n", "ifne",insn->label)
            break;
        case OP_IFLT: cj_mem_buf_printf(buf, "%s %d\n", "iflt", insn->label)
            break;
        case OP_IFGE: cj_mem_buf_printf(buf, "%s %d\n", "ifge", insn->label)
            break;
        case OP_IFGT: cj_mem_buf_printf(buf, "%s %d\n", "ifgt", insn->label)
            break;
        case OP_IFLE: cj_mem_buf_printf(buf, "%s %d\n", "ifle", insn->label)
            break;
        case OP_IF_ICMPEQ: cj_mem_buf_printf(buf, "%s %d\n", "if_icmpeq", insn->label)
            break;
        case OP_IF_ICMPNE: cj_mem_buf_printf(buf, "%s %d\n", "if_icmpne", insn->label)
            break;
        case OP_IF_ICMPLT: cj_mem_buf_printf(buf, "%s %d\n", "if_icmplt", insn->label)
            break;
        case OP_IF_ICMPGE: cj_mem_buf_printf(buf, "%s %d\n", "if_icmpge", insn->label)
            break;
        case OP_IF_ICMPGT: cj_mem_buf_printf(buf, "%s %d\n", "if_icmpgt", insn->label)
            break;
        case OP_IF_ICMPLE: cj_mem_buf_printf(buf, "%s %d\n", "if_icmple", insn->label)
            break;
        case OP_IF_ACMPEQ: cj_mem_buf_printf(buf, "%s %d\n", "if_acmpeq", insn->label)
            break;
        case OP_IF_ACMPNE: cj_mem_buf_printf(buf, "%s %d\n", "if_acmpne", insn->label)
            break;
        case OP_GETSTATIC: cj_mem_buf_printf(buf, "%s #%d\n", "getstatic", insn->cp_idx)
            break;
        case OP_PUTSTATIC: cj_mem_buf_printf(buf, "%s #%d\n", "putstatic", insn->cp_idx)
            break;
        case OP_GETFIELD: cj_mem_buf_printf(buf, "%s #%d\n", "getfield", insn->cp_idx)
            break;
        case OP_PUTFIELD: cj_mem_buf_printf(buf, "%s #%d\n", "putfield", insn->cp_idx)
            break;
        case OP_INVOKEVIRTUAL: cj_mem_buf_printf(buf, "%s #%d\n", "invokevirtual", insn->cp_idx)
            break;
        case OP_INVOKESPECIAL: cj_mem_buf_printf(buf, "%s #%d\n", "invokespecial", insn->cp_idx)
            break;
        case OP_INVOKESTATIC: cj_mem_buf_printf(buf, "%s #%d\n", "invokestatic", insn->cp_idx)
            break;
        case OP_INVOKEINTERFACE: cj_mem_buf_printf(buf, "%s #%d\n", "invokeinterface", insn->cp_idx)
            break;
        case OP_INVOKEDYNAMIC: cj_mem_buf_printf(buf, "%s #%d\n", "invokedynamic", insn->cp_idx)
            break;
        case OP_NEW: cj_mem_buf_printf(buf, "%s #%d\n", "new", insn->cp_idx)
            break;
        case OP_NEWARRAY: cj_mem_buf_printf(buf, "%s #%d\n", "newarray", insn->val)
            break;
        case OP_ANEWARRAY: cj_mem_buf_printf(buf, "%s #%d\n", "anewarray", insn->cp_idx)
            break;
        case OP_ARRAYLENGTH: cj_mem_buf_printf(buf, "%s", "arraylength\n")
            break;
        case OP_ATHROW: cj_mem_buf_printf(buf, "%s", "athrow\n")
            break;
        case OP_CHECKCAST: cj_mem_buf_printf(buf, "%s", "checkcast\n")
            break;
        case OP_INSTANCEOF: cj_mem_buf_printf(buf, "%s", "instanceof\n")
            break;
        case OP_MONITORENTER: cj_mem_buf_printf(buf, "%s", "monitorenter\n")
            break;
        case OP_MONITOREXIT: cj_mem_buf_printf(buf, "%s", "monitorexit\n")
            break;
        case OP_GOTO: cj_mem_buf_printf(buf, "%s %d\n", "goto", insn->label)
            break;
        case OP_JSR: cj_mem_buf_printf(buf, "%s %d\n", "jsr", insn->label)
            break;
        case OP_RET: cj_mem_buf_printf(buf, "%s", "ret\n")
            break;
        case OP_TABLESWITCH: {
            cj_mem_buf_printf(buf, "%s\n", "tableswitch {")
            i4 count = insn->s_high - insn->s_low + 1;
            for (int i = 0; i < count; ++i) {
                cj_mem_buf_printf(buf, "\t\t\t%d: %d\n", i + 1, insn->s_labels[i])
            }
            cj_mem_buf_printf(buf, "\t\t\tdefault: %d\n", insn->s_default)
            cj_mem_buf_printf(buf, "\t\t}\n")
            break;
        }
        case OP_LOOKUPSWITCH: {
            cj_mem_buf_printf(buf, "%s\n", "lookupswitch {")

            for (int i = 0; i < insn->s_pairs; ++i) {
                cj_mem_buf_printf(buf, "\t\t\t%d: %d\n", insn->s_keys[i], insn->s_labels[i])
            }

            cj_mem_buf_printf(buf, "\t\t}\n")
            break;
        }
        case OP_IRETURN: cj_mem_buf_printf(buf, "%s", "ireturn\n")
            break;
        case OP_LRETURN: cj_mem_buf_printf(buf, "%s", "lreturn\n")
            break;
        case OP_FRETURN: cj_mem_buf_printf(buf, "%s", "freturn\n")
            break;
        case OP_DRETURN: cj_mem_buf_printf(buf, "%s", "dreturn\n")
            break;
        case OP_ARETURN: cj_mem_buf_printf(buf, "%s", "areturn\n")
            break;
        case OP_RETURN: cj_mem_buf_printf(buf, "%s", "return\n")
            break;
        case OP_WIDE: cj_mem_buf_printf(buf, "%s", "wide\n")
            break;
        case OP_MULTIANEWARRAY: cj_mem_buf_printf(buf, "%s", "multianewarray\n")
            break;
        case OP_IFNULL: cj_mem_buf_printf(buf, "%s %d\n", "ifnull", insn->label)
            break;
        case OP_IFNONNULL: cj_mem_buf_printf(buf, "%s %d\n", "ifnonnull", insn->label)
            break;
        case OP_GOTO_W: cj_mem_buf_printf(buf, "%s %d\n", "goto_w", insn->label)
            break;
        case OP_JSR_W: cj_mem_buf_printf(buf, "%s %d\n", "jsr_w", insn->label)
            break;
        case OP_BREAKPOINT: cj_mem_buf_printf(buf, "%s", "breakpoint\n")
            break;
        case OP_IMPDEP1: cj_mem_buf_printf(buf, "%s", "impdep1\n")
            break;
        case OP_IMPDEP2: cj_mem_buf_printf(buf, "%s", "impdep2\n")
            break;
    }


}


void import_type(char *this_cls, struct hashmap_s *map, cj_type_t *type) {
    if (type->is_primitive) return;
    if (cj_streq(type->name, this_cls)) return;
    void *get = hashmap_get(map, type->name, strlen(type->name));
    if (get == NULL)
        hashmap_put(map, strdup(type->name), strlen(type->name), (void *) 0x1L);
}

int main(int argc, char **argv) {

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <class-file>\n", argv[0]);
        return 1;
    }

    char *path = argv[1];
    if (path == NULL) {
        fprintf(stderr, "Error: invalid argument[1] :%s\n", path);
        return 1;
    }

    unsigned char *buf = NULL;
    long len = cj_load_file(path, &buf);

    if (len <= 0) {
        fprintf(stderr, "Error: invalid class file size %lu \n", len);
        return 1;
    }

    cj_class_t *cls = cj_class_new(buf, len);
    if (cls == NULL) {
        fprintf(stderr, "Error: failed to parse class file\n");
        return 1;
    }
    free(buf);

    struct hashmap_s import_map;
    hashmap_create(64, &import_map);
    cj_mem_buf_t *out = cj_mem_buf_new();

    for (int i = 0; i < cj_class_get_annotation_count(cls); ++i) {
        cj_annotation_t *ann = cj_class_get_annotation(cls, i);

        cj_descriptor_t *descriptor = cj_descriptor_parse(ann->type_name, strlen((char *) ann->type_name));
        cj_type_t *type = descriptor->type;
        import_type((char *) cls->name, &import_map, type);
        cj_mem_buf_printf(out, "@%s", type->simple_name)
        if (ann->attributes_count > 0) {
            cj_mem_buf_printf(out, " ( ")
            for (int j = 0; j < ann->attributes_count; ++j) {
                cj_element_pair_t *pair = ann->attributes[j];
                u1 tag = pair->value->tag;
                switch (tag) {
                    case 'B': /*byte*/
                    case 'C': /*char*/
                    case 'I': /*int*/
                    case 'S': /*short*/
                    case 'Z': /*boolean*/
                    case 'F': /*float*/
                    {
                        cj_mem_buf_printf(out, "%s = %lul", pair->name, pair->value->const_num)
                        break;
                    }
                    case 'D': /*double*/
                    case 'J': /*long*/
                    {
                        cj_mem_buf_printf(out, "%s = %lul", pair->name, pair->value->const_num)
                        break;
                    }
                    case 's':/*string*/
                    {
                        cj_mem_buf_printf(out, "%s = %s", pair->name, pair->value->const_str)
                        break;
                    }
                    case 'e': /*enum*/
                    {
                        cj_mem_buf_printf(out, "%s = %s", pair->name, pair->value->const_name)
                        break;
                    }
                    case 'c': /*class*/
                    {
                        cj_mem_buf_printf(out, "%s = %d", pair->name, pair->value->class_info_index)
                        break;
                    }
                    case '@': /*annotation*/
                    {
                        cj_mem_buf_printf(out, "%s = ANNOTATION", pair->name)
                        break;
                    }
                    case '[': /*array*/
                    {
                        cj_mem_buf_printf(out, "%s = ARRAY", pair->name)
                        break;
                    }
                }
                if (j != ann->attributes_count - 1) {
                    cj_mem_buf_printf(out, "; ")
                }

            }
            cj_mem_buf_printf(out, " )")
        }
        cj_mem_buf_printf(out, "\n")

        cj_descriptor_free(descriptor);
    }

    u2 flags = cls->access_flags;
    if ((flags & ACC_PUBLIC) == ACC_PUBLIC) {
        cj_mem_buf_printf(out, "public ")
    }


    cj_mem_buf_printf(out, "class %s {\n", cls->short_name)

    for (int i = 0; i < cj_class_get_field_count(cls); ++i) {
        cj_field_t *field = cj_class_get_field(cls, i);

        cj_descriptor_t *desc = cj_descriptor_parse(field->descriptor, strlen((char *) field->descriptor));
        cj_type_t *type = desc->type;
        import_type((char *) cls->name, &import_map, type);

        cj_mem_buf_printf(out, "\t%s %s;\n", type->simple_name, field->name)
        cj_descriptor_free(desc);
    }

    cj_mem_buf_printf(out, "\n");
    for (int i = 0; i < cj_class_get_method_count(cls); ++i) {
        cj_method_t *method = cj_class_get_method(cls, i);

        cj_descriptor_t *descriptor = cj_method_get_descriptor(method);
        cj_type_t *type = descriptor->type;
        import_type((char *) cls->name, &import_map, type);
        if (strcmp((char *) method->name, "<init>") == 0) {
            cj_mem_buf_printf(out, "\t%s() {\n", cls->short_name)
        } else {
            cj_mem_buf_printf(out, "\t%s %s() {\n", type->simple_name, method->name)
        }


        cj_code_t *code = cj_method_get_code(method);

        cj_code_iter_t iter = cj_code_iter_start(code);
        while (cj_code_iter_has_next(&iter)) {
            cj_insn_t *insn = cj_code_iter_next(&iter);
            cj_mem_buf_printf(out, "%s", "\t\t")
            print_insn(out, insn);
            cj_insn_free(insn);
        }

        cj_exception_tab_t *exp_tab = code->exception_tab;
        if (exp_tab != NULL && exp_tab->length > 0) {
            cj_mem_buf_printf(out, "\t  Exception table: \n");
            cj_mem_buf_printf(out, "\t\tfrom\tto\ttarget\ttype\n");
            for (int j = 0; j < exp_tab->length; ++j) {
                cj_exception_t *exp = exp_tab->exceptions[j];
                const_str cat_name = cj_cp_get_class(cls, exp->catch_type);
                cj_mem_buf_printf(out, "\t\t%d\t\t%d\t\t%d\tClass %s\n", exp->start_pc, exp->end_pc,
                                  exp->handler_pc, cat_name);
            }
        }

        cj_line_number_tab_t *numbers = cj_code_get_line_number_table(code);
        if (numbers != NULL && numbers->length > 0) {

            cj_mem_buf_printf(out, "\t  LineNumberTable: \n");
            for (int j = 0; j < numbers->length; ++j) {
                cj_line_number_t *num = numbers->line_numbers[j];
                cj_mem_buf_printf(out, "\t\t\tline %d: %d\n", num->number, num->start_pc);
            }
        }


        cj_mem_buf_printf(out, "\t}\n\n")
    }

    cj_mem_buf_printf(out, "}\n")

    printf("package %s;\n\n", cls->package);

    for (int i = 0; i < import_map.table_size; i++) {
        if (import_map.data[i].in_use) {
            printf("import %s;\n", import_map.data[i].key);
            free((void *) import_map.data[i].key);
        }
    }
    printf("\n");

    cj_mem_buf_write_u1(out, 0);
    cj_mem_buf_flush(out);
    printf("%s\n", out->data);
    cj_mem_buf_free(out);

    hashmap_destroy(&import_map);

    cj_class_free(cls);
    return 0;
}

