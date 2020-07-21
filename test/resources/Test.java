package io.ticup.example;

import java.util.Random;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@interface Ann {
    String name();
    int age() default 0;
    double balance();
}


@Retention(RetentionPolicy.RUNTIME)
@interface VisibleAnn {
    String[] types();
}

@Deprecated
@Ann(name = "hello", balance = 8.89)
public final class Test {

    @Ann(name = "CONSTRUCTOR_TEST", balance = 9.9911, age = 12)
    @VisibleAnn(types= {"v_hello_0", "v_hello_0"})
    private String name;
    private Test parent;
    private Integer age = 22222;
    private Double balance;


    @Ann(name = "CONSTRUCTOR_TEST", balance = 9.9911)
    @VisibleAnn(types= {"v_hello_1", "v_hello_2"})
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



    }

    public void sayBye() {
        long var1 = System.currentTimeMillis();
        System.out.println("Bye");
        long var2 = System.currentTimeMillis() - var1;
        String s = "Bye bye";
        System.out.println(var2 + s);
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
