//
// Created by Rieon Ke on 2020/7/15.
//

#include "util.h"

long cj_load_file(char *path, unsigned char **buf) {

    FILE *f = NULL;
    long len;

#ifdef _WIN32
    fopen_s(&f, path, "rb");
#else
    f = fopen(path,"rb");
#endif
    if (!f) {
        return -1;
    }

    fseek(f, 0, SEEK_END);
    len = ftell(f);
    fseek(f, 0, SEEK_SET);

    *buf = calloc(len, sizeof(char));

#ifdef _WIN32
    fread_s(*buf, len, sizeof(char), len, f);
#else
    fread(*buf,  sizeof(char), len, f);
#endif
    fclose(f);

    return len;
}


