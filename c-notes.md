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

- Explicitly initialize variables

        static int lenFile = 0;          /* Length of the zFile name */

**Integer Variables names**

- Prefix length of objects with `len`

        static int lenFile = 0;          /* Length of the zFile name */

- Prefix count of objects with `n`. Singular.

        static int nRequest = 0;         /* Number of requests processed */

- Boolean states and settings read well when prefix with `if`

        # if status sent
        static int statusSent = 0;       /* True after status line is sent */

        # if use HTTPS
        static int useHttps = 0;         /* True to use HTTPS: instead of HTTP: */

        # if IP v6 only
        static int ipv6Only = 0;         /* Use IPv6 only */

- Prefix max, min values with max, min. No abbrievations.

        static int maxCpu = MAX_CPU;     /* Maximum CPU time per process */


