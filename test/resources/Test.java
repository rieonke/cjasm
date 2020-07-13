package io.ticup.example;

import java.lang.*;

@Deprecated
public class Test {

    private String name;
    private Test parent;
    private int age;
    private Double balance;


    public void sayBye() {
        long var1 = System.currentTimeMillis();
        System.out.println("Bye");
        long var2 = System.currentTimeMillis() - var1;
        System.out.println(var2);
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
