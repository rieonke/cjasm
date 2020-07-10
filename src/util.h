//
// Created by Rieon Ke on 2020/7/10.
//

#ifndef CJASM_UTIL_H
#define CJASM_UTIL_H

#include <cjasm.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#if defined(__APPLE__)

#include <machine/endian.h>
#include <libkern/OSByteOrder.h>

#if BYTE_ORDER == LITTLE_ENDIAN

#define btol16(x) OSSwapInt16(x)
#define btol32(x) OSSwapInt32(x)
#define btol64(x) OSSwapInt64(x)

#elif BYTE_ORDER == BIG_ENDIAN

#define btol16(x) (x)
#define btol32(x) (x)
#define btol64(x) (x)

#endif


#else

#error "unsupported os type"

#endif

//todo impl windows & linux

#define cj_ri1(ptr) (*(i1 *) (ptr))
#define cj_ri2(ptr) btol16(*(i2 *) (ptr))
#define cj_ri4(ptr) btol32(*(i4 *) (ptr))
#define cj_ru1(ptr) (*(u1 *) (ptr))
#define cj_ru2(ptr) btol16(*(u2 *) (ptr))
#define cj_ru4(ptr) btol32(*(u4 *) (ptr))
#define cj_ru8(ptr) btol64(*(u8 *) (ptr))


//@formatter:off
enum cj_cp_type {
    CONSTANT_Class              =   7 ,
    CONSTANT_Fieldref           =   9 ,
    CONSTANT_Methodref          =  10 ,
    CONSTANT_InterfaceMethodref =  11 ,
    CONSTANT_String             =   8 ,
    CONSTANT_Integer            =   3 ,
    CONSTANT_Float              =   4 ,
    CONSTANT_Long               =   5 ,
    CONSTANT_Double             =   6 ,
    CONSTANT_NameAndType        =  12 ,
    CONSTANT_Utf8               =   1 ,
    CONSTANT_MethodHandle       =  15 ,
    CONSTANT_MethodType         =  16 ,
    CONSTANT_Dynamic            =  17 ,
    CONSTANT_InvokeDynamic      =  18 ,
    CONSTANT_Module             =  19 ,
    CONSTANT_Package            =  20 ,
};
//@formatter:on

static void print_type(enum cj_cp_type t) {

#define PRINT_TYPE(t) \
    case t: \
        printf("%s\n", #t);\
        break;

    switch (t) {
        PRINT_TYPE(CONSTANT_Class)
        PRINT_TYPE(CONSTANT_Fieldref)
        PRINT_TYPE(CONSTANT_Methodref)
        PRINT_TYPE(CONSTANT_InterfaceMethodref)
        PRINT_TYPE(CONSTANT_String)
        PRINT_TYPE(CONSTANT_Integer)
        PRINT_TYPE(CONSTANT_Float)
        PRINT_TYPE(CONSTANT_Long)
        PRINT_TYPE(CONSTANT_Double)
        PRINT_TYPE(CONSTANT_NameAndType)
        PRINT_TYPE(CONSTANT_Utf8)
        PRINT_TYPE(CONSTANT_MethodHandle)
        PRINT_TYPE(CONSTANT_MethodType)
        PRINT_TYPE(CONSTANT_Dynamic)
        PRINT_TYPE(CONSTANT_InvokeDynamic)
        PRINT_TYPE(CONSTANT_Module)
        PRINT_TYPE(CONSTANT_Package)
    }

#undef PRINT_TYPE
}

#endif //CJASM_UTIL_H
