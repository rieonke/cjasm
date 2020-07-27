//
// Created by Rieon Ke on 2020/7/21.
//

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "cjasm.h"
#include "../src/cpool.h"
#include "../src/class.h"
#include "../src/field.h"
#include <setjmp.h>
#include <cmocka.h>


#define TEST_CLASS "io/ticup/example/Test.class"
#define MAJOR_VERSION 52
#define MINOR_VERSION 0

#define CTX ((cj_class_t*)*state)

static int setup(void **state) {

    unsigned char *buf = NULL;
    long len = cj_load_file(TEST_CLASS, &buf);
    assert(len > 0);
    assert_non_null(buf);

    *state = cj_class_new(buf, len);

    free(buf);

    assert_non_null(state);
    return 0;
}

static int teardown(void **state) {
    cj_class_free(CTX);
    return 0;
}

void test_check_write(void **state) {

    cj_class_set_name(CTX, (unsigned char *) "Test1");
    char *str = "Too cultivated use solicitude frequently. Dashwood likewise up consider continue entrance ladyship oh. Wrong guest given purse power is no. Friendship to connection an am considered difficulty. Country met pursuit lasting moments why calling certain the. Middletons boisterous our way understood law. Among state cease how and sight since shall. Material did pleasure breeding our humanity she contempt had. So ye really mutual no cousin piqued summer result. \n"
                "Looking started he up perhaps against. How remainder all additions get elsewhere resources. One missed shy wishes supply design answer formed. Prevent on present hastily passage an subject in be. Be happiness arranging so newspaper defective affection ye. Families blessing he in to no daughter. \n"
                "Death weeks early had their and folly timed put. Hearted forbade on an village ye in fifteen. Age attended betrayed her man raptures laughter. Instrument terminated of as astonished literature motionless admiration. The affection are determine how performed intention discourse but. On merits on so valley indeed assure of. Has add particular boisterous uncommonly are. Early wrong as so manor match. Him necessary shameless discovery consulted one but. \n"
                "Sense child do state to defer mr of forty. Become latter but nor abroad wisdom waited. Was delivered gentleman acuteness but daughters. In as of whole as match asked. Pleasure exertion put add entrance distance drawings. In equally matters showing greatly it as. Want name any wise are able park when. Saw vicinity judgment remember finished men throwing. \n"
                "In on announcing if of comparison pianoforte projection. Maids hoped gay yet bed asked blind dried point. On abroad danger likely regret twenty edward do. Too horrible consider followed may differed age. An rest if more five mr of. Age just her rank met down way. Attended required so in cheerful an. Domestic replying she resolved him for did. Rather in lasted no within no. \n"
                "Son agreed others exeter period myself few yet nature. Mention mr manners opinion if garrets enabled. To an occasional dissimilar impossible sentiments. Do fortune account written prepare invited no passage. Garrets use ten you the weather ferrars venture friends. Solid visit seems again you nor all. \n"
                "Ten the hastened steepest feelings pleasant few surprise property. An brother he do colonel against minutes uncivil. Can how elinor warmly mrs basket marked. Led raising expense yet demesne weather musical. Me mr what park next busy ever. Elinor her his secure far twenty eat object. Late any far saw size want man. Which way you wrong add shall one. As guest right of he scale these. Horses nearer oh elinor of denote. \n"
                "Wise busy past both park when an ye no. Nay likely her length sooner thrown sex lively income. The expense windows adapted sir. Wrong widen drawn ample eat off doors money. Offending belonging promotion provision an be oh consulted ourselves it. Blessing welcomed ladyship she met humoured sir breeding her. Six curiosity day assurance bed necessary. \n"
                "Nor hence hoped her after other known defer his. For county now sister engage had season better had waited. Occasional mrs interested far expression acceptance. Day either mrs talent pulled men rather regret admire but. Life ye sake it shed. Five lady he cold in meet up. Service get met adapted matters offence for. Principles man any insipidity age you simplicity understood. Do offering pleasure no ecstatic whatever on mr directly. \n"
                "It as announcing it me stimulated frequently continuing. Least their she you now above going stand forth. He pretty future afraid should genius spirit on. Set property addition building put likewise get. Of will at sell well at as. Too want but tall nay like old. Removing yourself be in answered he. Consider occasion get improved him she eat. Letter by lively oh denote an. \n";
    u2 idx = 0;
    cj_cp_put_str(CTX, (unsigned char *) str, strlen(str), &idx);

    assert_string_equal(CTX->name, "Test1");

    for (int i = 0; i < CTX->field_count; ++i) {
        cj_field_t *field = cj_class_get_field(CTX, i);
        if (strstr((char *) field->name, "name") == (char *) field->name && strlen((char *) field->name) > 4) {
            cj_class_remove_field(CTX, i);
        }
    }


    cj_field_t *field = cj_field_new(CTX, 0x2, (const_str) "hello_field", (const_str) "I");

    cj_class_add_field(CTX, field);


    cj_mem_buf_t *out = cj_class_to_buf(CTX);
    size_t len = out->length;

    cj_class_t *cls = cj_class_new(out->data, out->length);
//    const_str str1 = cj_cp_get_str(cls, idx);
//    assert_string_equal(str,str1);

    FILE *f = fopen("Test1.class", "wb");
    fwrite(out->data, sizeof(u1), len, f);
    fclose(f);

    cj_mem_buf_free(out);

    assert_non_null(cls->name != NULL);
    cj_class_free(cls);
}

int main(void) {

    const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_check_write),
    };

    return cmocka_run_group_tests(tests, setup, teardown);
}
