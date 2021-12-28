# C Notes

**static int aLocalFunction() {...}**

A `static` function is one that is visible only within the source file
containing the function definition.


**int aGlobalFunction() {...}**

By default, all functions are visible in all files.


**static int a[10]**

A `static variable has block-scope and static storage duration.


**Storage Duration**

- static        In data segment of program in memory
                Generated and initialized before execution of program
                Visible for entire process runtime
                Applied to objects outside all functions or within
                  functions with the `static` keyword

- automatic     On the stack at runtime
                Applied to objects defined within functions with no
                  `static` keyword

- allocated     Obtained at runtime from the heap


----
# Style Recommendations

- Define functions as static

        static int aLocalFunction() {...}

- Explicitly define variables

        static int nIn = 0;

