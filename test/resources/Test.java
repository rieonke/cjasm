package io.ticup.example;

import java.util.Random;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@interface Ann {
    String name();

    int age() default 0;

    long num() default 0l;

    float tax() default 0.0f;

    double balance() default 0.0d;
}


@Retention(RetentionPolicy.RUNTIME)
@interface VisibleAnn {
    String[] types();
}

@Deprecated
@Ann(name = "hello", balance = 8.89)
public final class Test {

    @Ann(name = "CONSTRUCTOR_TEST", balance = 9.9911d, age = 12, num = 1234567890l, tax = 0.032f)
    @VisibleAnn(types = {"v_hello_0", "v_hello_0"})
    private String name;
    private Test parent;
    private Integer age = 22221112;
    private Double balance = 22.2;

    private static char[] ALPHA_LIST = {
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
            'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
            'U', 'V', 'W', 'X', 'Y', 'Z'
    };


    @Ann(name = "CONSTRUCTOR_TEST", balance = 9.9911d)
    @VisibleAnn(types = {"v_hello_1", "v_hello_2"})
    public Test() {

        Random r = new Random();
        int i = r.nextInt();
        System.out.println(this.age);

        switch (i) {
            case 1:
                System.out.println("first");
                break;
            case 2:
                System.out.println("second");
                break;
            case 3:
                System.out.println("sorry");
            default:
                System.out.println("undefined");
                break;
        }

        switch (i) {

            case 3:
                System.out.println("THREE");
                break;
            case 8:
                System.out.println("EIGHT");
            case 10:
                System.out.println("TEN");

            default:
                break;
        }

        char[] strBuf = new char[3];

        for (int i1 = 0; i1 < 3; i1++) {
            int idx = r.nextInt(36);
            strBuf[i1] = ALPHA_LIST[idx];
        }

        String str = new String(strBuf);
        switch (str) {
            case "ABC":
                System.out.println("一等奖");
                break;
            case "BCD":
                System.out.println("二等奖");
                break;
            case "123":
                System.out.println("三等奖");
                break;
            default:
                System.out.println("谢谢参与");
        }


    }

    public Test getParent() {
        return null;
    }

    public void sayBye() {
        long var1 = System.currentTimeMillis();
        System.out.println("Bye");
        long var2 = System.currentTimeMillis() - var1;
        String s = "Bye bye";
        System.out.println(var2 + s);

        Test t = getParent();
        assert t != null;

    }

    public static void main(String[] args) throws InterruptedException, ClassNotFoundException, IllegalAccessException, InstantiationException {

        Test t = new Test();
        t.sayBye();

        Thread.sleep(5000);

        Class<?> aClass = Class.forName("io.ticup.example.LazyLoad");

        Thread.sleep(3000);
        Object o = aClass.newInstance();

        while (true) {
            Thread.sleep(1000);
        }
    }

}
