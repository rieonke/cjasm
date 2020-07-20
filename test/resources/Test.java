package io.ticup.example;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@interface Ann {
    String name();

    double balance();
}


@Retention(RetentionPolicy.RUNTIME)
@interface VisibleAnn {
    String[] types();
}

@Deprecated
@Ann(name = "hello", balance = 8.89)
public class Test {

    private String name;
    private Test parent;
    private int age;
    private Double balance;


    @Ann(name = "CONSTRUCTOR_TEST", balance = 9.9911)
    @VisibleAnn(types= {"v_hello_1", "v_hello_2"})
    public Test() {

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
