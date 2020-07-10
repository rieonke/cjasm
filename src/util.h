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

#define btol32 ntohl
#define btol16 ntohs
#define btol64 ntohll


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

#define tos(v) #v

static void print_type(enum cj_cp_type t) {

    switch (t) {

        case CONSTANT_Class:
            printf("%s\n", tos(CONSTANT_Class));
            break;
        case CONSTANT_Fieldref:
            printf("%s\n", tos(CONSTANT_Fieldref));
            break;
        case CONSTANT_Methodref:
            printf("%s\n", tos(CONSTANT_Methodref));
            break;
        case CONSTANT_InterfaceMethodref:
            printf("%s\n", tos(CONSTANT_InterfaceMethodref));
            break;
        case CONSTANT_String:
            printf("%s\n", tos(CONSTANT_String));
            break;
        case CONSTANT_Integer:
            printf("%s\n", tos(CONSTANT_Integer));
            break;
        case CONSTANT_Float:
            printf("%s\n", tos(CONSTANT_Float));
            break;
        case CONSTANT_Long:
            printf("%s\n", tos(CONSTANT_Long));
            break;
        case CONSTANT_Double:
            printf("%s\n", tos(CONSTANT_Double));
            break;
        case CONSTANT_NameAndType:
            printf("%s\n", tos(CONSTANT_NameAndType));
            break;
        case CONSTANT_Utf8:
            printf("%s\n", tos(CONSTANT_Utf8));
            break;
        case CONSTANT_MethodHandle:
            printf("%s\n", tos(CONSTANT_MethodHandle));
            break;
        case CONSTANT_MethodType:
            printf("%s\n", tos(CONSTANT_MethodType));
            break;
        case CONSTANT_Dynamic:
            printf("%s\n", tos(CONSTANT_Dynamic));
            break;
        case CONSTANT_InvokeDynamic:
            printf("%s\n", tos(CONSTANT_InvokeDynamic));
            break;
        case CONSTANT_Module:
            printf("%s\n", tos(CONSTANT_Module));
            break;
        case CONSTANT_Package:
            printf("%s\n", tos(CONSTANT_Package));
            break;
    }

}


static inline i1 cj_ri1(const unsigned char *ptr) {
    return *(i1 *) (ptr);
}

static inline i2 cj_ri2(const unsigned char *ptr) {
    return btol16(*(i2 *) (ptr));
}

static inline i4 cj_ri4(const unsigned char *ptr) {
    return btol32(*(i4 *) (ptr));
}

static inline u1 cj_ru1(const unsigned char *ptr) {
    return *(u1 *) (ptr);
}

static inline u2 cj_ru2(const unsigned char *ptr) {
    return btol16(*(u2 *) (ptr));
}

static inline u4 cj_ru4(const unsigned char *ptr) {
    return btol32(*(u4 *) (ptr));
}

static inline u8 cj_ru8(const unsigned char *ptr) {
    return btol64(*(u8 *) (ptr));
}


#endif //CJASM_UTIL_H
