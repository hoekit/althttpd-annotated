     1	/*
     2	** 2001-09-15
     3	**
     4	** The author disclaims copyright to this source code.  In place of
     5	** a legal notice, here is a blessing:
     6	**
     7	**    May you do good and not evil.
     8	**    May you find forgiveness for yourself and forgive others.
     9	**    May you share freely, never taking more than you give.
    10	**
    11	*************************************************************************
    12	**
    13	** This source code file implements a small, simple, stand-alone HTTP
    14	** server.  
    15	**
    16	** Features:
    17	**
    18	**     * Launched from inetd/xinetd/stunnel4, or as a stand-alone server
    19	**     * One process per request
    20	**     * Deliver static content or run CGI or SCGI
    21	**     * Virtual sites based on the "Host:" property of the HTTP header
    22	**     * Runs in a chroot jail
    23	**     * Unified log file in a CSV format
    24	**     * Small code base (this 1 file) to facilitate security auditing
    25	**     * Simple setup - no configuration files to misconfigure
    26	** 
    27	** This file implements a small and simple but secure and effective web
    28	** server.  There are no frills.  Anything that could be reasonably
    29	** omitted has been.
    30	**
    31	** Setup rules:
    32	**
    33	**    (1) Launch as root from inetd like this:
    34	**
    35	**            httpd -logfile logfile -root /home/www -user nobody
    36	**
    37	**        It will automatically chroot to /home/www and become user "nobody".
    38	**        The logfile name should be relative to the chroot jail.
    39	**
    40	**    (2) Directories of the form "*.website" (ex: www_sqlite_org.website)
    41	**        contain content.  The directory is chosen based on the HTTP_HOST
    42	**        request header.  If there is no HTTP_HOST header or if the
    43	**        corresponding host directory does not exist, then the
    44	**        "default.website" is used.  If the HTTP_HOST header contains any
    45	**        charaters other than [a-zA-Z0-9_.,*~/] then a 403 error is
    46	**        generated.
    47	**
    48	**    (3) Any file or directory whose name begins with "." or "-" is ignored,
    49	**        except if the URL begins with "/.well-known/" then initial "." and
    50	**        "-" characters are allowed, but not initial "..".  The exception is
    51	**        for RFC-5785 to allow letsencrypt or certbot to generate a TLS cert
    52	**        using webroot.
    53	**
    54	**    (4) Characters other than [0-9a-zA-Z,-./:_~] and any %HH characters
    55	**        escapes in the filename are all translated into "_".  This is
    56	**        a defense against cross-site scripting attacks and other mischief.
    57	**
    58	**    (5) Executable files are run as CGI.  Files whose name ends with ".scgi"
    59	**        trigger and SCGI request (see item 10 below).  All other files
    60	**        are delivered as is.
    61	**
    62	**    (6) For SSL support use stunnel and add the -https 1 option on the
    63	**        httpd command-line.
    64	**
    65	**    (7) If a file named "-auth" exists in the same directory as the file to
    66	**        be run as CGI or to be delivered, then it contains information
    67	**        for HTTP Basic authorization.  See file format details below.
    68	**
    69	**    (8) To run as a stand-alone server, simply add the "-port N" command-line
    70	**        option to define which TCP port to listen on.
    71	**
    72	**    (9) For static content, the mimetype is determined by the file suffix
    73	**        using a table built into the source code below.  If you have
    74	**        unusual content files, you might need to extend this table.
    75	**
    76	**   (10) Content files that end with ".scgi" and that contain text of the
    77	**        form "SCGI hostname port" will format an SCGI request and send it
    78	**        to hostname:port, the relay back the reply.  Error behavior is
    79	**        determined by subsequent lines of the .scgi file.  See SCGI below
    80	**        for details.
    81	**
    82	** Command-line Options:
    83	**
    84	**  --root DIR       Defines the directory that contains the various
    85	**                   $HOST.website subdirectories, each containing web content 
    86	**                   for a single virtual host.  If launched as root and if
    87	**                   "--user USER" also appears on the command-line and if
    88	**                   "--jail 0" is omitted, then the process runs in a chroot
    89	**                   jail rooted at this directory and under the userid USER.
    90	**                   This option is required for xinetd launch but defaults
    91	**                   to "." for a stand-alone web server.
    92	**
    93	**  --port N         Run in standalone mode listening on TCP port N
    94	**
    95	**  --user USER      Define the user under which the process should run if
    96	**                   originally launched as root.  This process will refuse to
    97	**                   run as root (for security).  If this option is omitted and
    98	**                   the process is launched as root, it will abort without
    99	**                   processing any HTTP requests.
   100	**
   101	**  --logfile FILE   Append a single-line, CSV-format, log file entry to FILE
   102	**                   for each HTTP request.  FILE should be a full pathname.
   103	**                   The FILE name is interpreted inside the chroot jail.  The
   104	**                   FILE name is expanded using strftime() if it contains
   105	**                   at least one '%' and is not too long.
   106	**
   107	**  --https          Indicates that input is coming over SSL and is being
   108	**                   decoded upstream, perhaps by stunnel.  (This program
   109	**                   only understands plaintext.)
   110	**
   111	**  --family ipv4    Only accept input from IPV4 or IPV6, respectively.
   112	**  --family ipv6    These options are only meaningful if althttpd is run
   113	**                   as a stand-alone server.
   114	**
   115	**  --jail BOOLEAN   Indicates whether or not to form a chroot jail if 
   116	**                   initially run as root.  The default is true, so the only
   117	**                   useful variant of this option is "--jail 0" which prevents
   118	**                   the formation of the chroot jail.
   119	**
   120	**  --max-age SEC    The value for "Cache-Control: max-age=%d".  Defaults to
   121	**                   120 seconds.
   122	**
   123	**  --max-cpu SEC    Maximum number of seconds of CPU time allowed per
   124	**                   HTTP connection.  Default 30.  0 means no limit.
   125	**
   126	**  --debug          Disables input timeouts.  This is useful for debugging
   127	**                   when inputs is being typed in manually.
   128	**
   129	** Command-line options can take either one or two initial "-" characters.
   130	** So "--debug" and "-debug" mean the same thing, for example.
   131	**
   132	**
   133	** Security Features:
   134	**
   135	** (1)  This program automatically puts itself inside a chroot jail if
   136	**      it can and if not specifically prohibited by the "--jail 0"
   137	**      command-line option.  The root of the jail is the directory that
   138	**      contains the various $HOST.website content subdirectories.
   139	**
   140	** (2)  No input is read while this process has root privileges.  Root
   141	**      privileges are dropped prior to reading any input (but after entering
   142	**      the chroot jail, of course).  If root privileges cannot be dropped
   143	**      (for example because the --user command-line option was omitted or
   144	**      because the user specified by the --user option does not exist), 
   145	**      then the process aborts with an error prior to reading any input.
   146	**
   147	** (3)  The length of an HTTP request is limited to MAX_CONTENT_LENGTH bytes
   148	**      (default: 250 million).  Any HTTP request longer than this fails
   149	**      with an error.
   150	**
   151	** (4)  There are hard-coded time-outs on each HTTP request.  If this process
   152	**      waits longer than the timeout for the complete request, or for CGI
   153	**      to finish running, then this process aborts.  (The timeout feature
   154	**      can be disabled using the --debug command-line option.)
   155	**
   156	** (5)  If the HTTP_HOST request header contains characters other than
   157	**      [0-9a-zA-Z,-./:_~] then the entire request is rejected.
   158	**
   159	** (6)  Any characters in the URI pathname other than [0-9a-zA-Z,-./:_~]
   160	**      are converted into "_".  This applies to the pathname only, not
   161	**      to the query parameters or fragment.
   162	**
   163	** (7)  If the first character of any URI pathname component is "." or "-"
   164	**      then a 404 Not Found reply is generated.  This prevents attacks
   165	**      such as including ".." or "." directory elements in the pathname
   166	**      and allows placing files and directories in the content subdirectory
   167	**      that are invisible to all HTTP requests, by making the first 
   168	**      character of the file or subdirectory name "-" or ".".
   169	**
   170	** (8)  The request URI must begin with "/" or else a 404 error is generated.
   171	**
   172	** (9)  This program never sets the value of an environment variable to a
   173	**      string that begins with "() {".
   174	**
   175	** Security Auditing:
   176	**
   177	** This webserver mostly only serves static content.  Any security risk will
   178	** come from CGI and SCGI.  To check an installation for security, then, it
   179	** makes sense to focus on the CGI and SCGI scripts.
   180	**
   181	** To local all CGI files:
   182	**
   183	**          find *.website -executable -type f -print
   184	**     OR:  find *.website -perm +0111 -type f -print
   185	**
   186	** The first form of the "find" command is preferred, but is only supported
   187	** by GNU find.  On a Mac, you'll have to use the second form.
   188	**
   189	** To find all SCGI files:
   190	**
   191	**          find *.website -name '*.scgi' -type f -print
   192	**
   193	** If any file is a security concern, it can be disabled on a live
   194	** installation by turning off read permissions:
   195	**
   196	**          chmod 0000 file-of-concern
   197	**
   198	** SCGI Specification Files:
   199	**
   200	** Content files (files without the execute bit set) that end with ".scgi"
   201	** specify a connection to an SCGI server.  The format of the .scgi file
   202	** follows this template:
   203	**
   204	**      SCGI hostname port
   205	**      fallback: fallback-filename
   206	**      relight: relight-command
   207	**
   208	** The first line specifies the location and TCP/IP port of the SCGI server
   209	** that will handle the request.  Subsequent lines determine what to do if
   210	** the SCGI server cannot be contacted.  If the "relight:" line is present,
   211	** then the relight-command is run using system() and the connection is
   212	** retried after a 1-second delay.  Use "&" at the end of the relight-command
   213	** to run it in the background.  Make sure the relight-command does not
   214	** send generate output, or that output will become part of the SCGI reply.
   215	** Add a ">/dev/null" suffix (before the "&") to the relight-command if
   216	** necessary to suppress output.  If there is no relight-command, or if the
   217	** relight is attempted but the SCGI server still cannot be contacted, then
   218	** the content of the fallback-filename file is returned as a substitute for
   219	** the SCGI request.  The mimetype is determined by the suffix on the
   220	** fallback-filename.  The fallback-filename would typically be an error
   221	** message indicating that the service is temporarily unavailable.
   222	**
   223	** Basic Authorization:
   224	**
   225	** If the file "-auth" exists in the same directory as the content file
   226	** (for both static content and CGI) then it contains the information used
   227	** for basic authorization.  The file format is as follows:
   228	**
   229	**    *  Blank lines and lines that begin with '#' are ignored
   230	**    *  "http-redirect" forces a redirect to HTTPS if not there already
   231	**    *  "https-only" disallows operation in HTTP
   232	**    *  "user NAME LOGIN:PASSWORD" checks to see if LOGIN:PASSWORD 
   233	**       authorization credentials are provided, and if so sets the
   234	**       REMOTE_USER to NAME.
   235	**    *  "realm TEXT" sets the realm to TEXT.
   236	**
   237	** There can be multiple "user" lines.  If no "user" line matches, the
   238	** request fails with a 401 error.
   239	**
   240	** Because of security rule (7), there is no way for the content of the "-auth"
   241	** file to leak out via HTTP request.
   242	*/
   243	#include <stdio.h>
   244	#include <ctype.h>
   245	#include <syslog.h>
   246	#include <stdlib.h>
   247	#include <sys/stat.h>
   248	#include <unistd.h>
   249	#include <fcntl.h>
   250	#include <string.h>
   251	#include <pwd.h>
   252	#include <sys/time.h>
   253	#include <sys/types.h>
   254	#include <sys/resource.h>
   255	#include <sys/socket.h>
   256	#include <sys/wait.h>
   257	#include <netinet/in.h>
   258	#include <arpa/inet.h>
   259	#include <stdarg.h>
   260	#include <time.h>
   261	#include <sys/times.h>
   262	#include <netdb.h>
   263	#include <errno.h>
   264	#include <sys/resource.h>
   265	#include <signal.h>
   266	#ifdef linux
   267	#include <sys/sendfile.h>
   268	#endif
   269	#include <assert.h>
   270	
   271	/*
   272	** Configure the server by setting the following macros and recompiling.
   273	*/
   274	#ifndef DEFAULT_PORT
   275	#define DEFAULT_PORT "80"             /* Default TCP port for HTTP */
   276	#endif
   277	#ifndef MAX_CONTENT_LENGTH
   278	#define MAX_CONTENT_LENGTH 250000000  /* Max length of HTTP request content */
   279	#endif
   280	#ifndef MAX_CPU
   281	#define MAX_CPU 30                /* Max CPU cycles in seconds */
   282	#endif
   283	
   284	/*
   285	** We record most of the state information as global variables.  This
   286	** saves having to pass information to subroutines as parameters, and
   287	** makes the executable smaller...
   288	*/
   289	static char *zRoot = 0;          /* Root directory of the website */
   290	static char *zTmpNam = 0;        /* Name of a temporary file */
   291	static char zTmpNamBuf[500];     /* Space to hold the temporary filename */
   292	static char *zProtocol = 0;      /* The protocol being using by the browser */
   293	static char *zMethod = 0;        /* The method.  Must be GET */
   294	static char *zScript = 0;        /* The object to retrieve */
   295	static char *zRealScript = 0;    /* The object to retrieve.  Same as zScript
   296	                                 ** except might have "/index.html" appended */
   297	static char *zHome = 0;          /* The directory containing content */
   298	static char *zQueryString = 0;   /* The query string on the end of the name */
   299	static char *zFile = 0;          /* The filename of the object to retrieve */
   300	static int lenFile = 0;          /* Length of the zFile name */
   301	static char *zDir = 0;           /* Name of the directory holding zFile */
   302	static char *zPathInfo = 0;      /* Part of the pathname past the file */
   303	static char *zAgent = 0;         /* What type if browser is making this query */
   304	static char *zServerName = 0;    /* The name after the http:// */
   305	static char *zServerPort = 0;    /* The port number */
   306	static char *zCookie = 0;        /* Cookies reported with the request */
   307	static char *zHttpHost = 0;      /* Name according to the web browser */
   308	static char *zRealPort = 0;      /* The real TCP port when running as daemon */
   309	static char *zRemoteAddr = 0;    /* IP address of the request */
   310	static char *zReferer = 0;       /* Name of the page that refered to us */
   311	static char *zAccept = 0;        /* What formats will be accepted */
   312	static char *zAcceptEncoding =0; /* gzip or default */
   313	static char *zContentLength = 0; /* Content length reported in the header */
   314	static char *zContentType = 0;   /* Content type reported in the header */
   315	static char *zQuerySuffix = 0;   /* The part of the URL after the first ? */
   316	static char *zAuthType = 0;      /* Authorization type (basic or digest) */
   317	static char *zAuthArg = 0;       /* Authorization values */
   318	static char *zRemoteUser = 0;    /* REMOTE_USER set by authorization module */
   319	static char *zIfNoneMatch= 0;    /* The If-None-Match header value */
   320	static char *zIfModifiedSince=0; /* The If-Modified-Since header value */
   321	static int nIn = 0;              /* Number of bytes of input */
   322	static int nOut = 0;             /* Number of bytes of output */
   323	static char zReplyStatus[4];     /* Reply status code */
   324	static int statusSent = 0;       /* True after status line is sent */
   325	static char *zLogFile = 0;       /* Log to this file */
   326	static int debugFlag = 0;        /* True if being debugged */
   327	static struct timeval beginTime; /* Time when this process starts */
   328	static int closeConnection = 0;  /* True to send Connection: close in reply */
   329	static int nRequest = 0;         /* Number of requests processed */
   330	static int omitLog = 0;          /* Do not make logfile entries if true */
   331	static int useHttps = 0;         /* True to use HTTPS: instead of HTTP: */
   332	static char *zHttp = "http";     /* http or https */
   333	static int useTimeout = 1;       /* True to use times */
   334	static int standalone = 0;       /* Run as a standalone server (no inetd) */
   335	static int ipv6Only = 0;         /* Use IPv6 only */
   336	static int ipv4Only = 0;         /* Use IPv4 only */
   337	static struct rusage priorSelf;  /* Previously report SELF time */
   338	static struct rusage priorChild; /* Previously report CHILD time */
   339	static int mxAge = 120;          /* Cache-control max-age */
   340	static char *default_path = "/bin:/usr/bin";  /* Default PATH variable */
   341	static char *zScgi = 0;          /* Value of the SCGI env variable */
   342	static int rangeStart = 0;       /* Start of a Range: request */
   343	static int rangeEnd = 0;         /* End of a Range: request */
   344	static int maxCpu = MAX_CPU;     /* Maximum CPU time per process */
   345	
   346	/*
   347	** Mapping between CGI variable names and values stored in
   348	** global variables.
   349	*/
   350	static struct {
   351	  char *zEnvName;
   352	  char **pzEnvValue;
   353	} cgienv[] = {
   354	  { "CONTENT_LENGTH",          &zContentLength }, /* Must be first for SCGI */
   355	  { "AUTH_TYPE",                   &zAuthType },
   356	  { "AUTH_CONTENT",                &zAuthArg },
   357	  { "CONTENT_TYPE",                &zContentType },
   358	  { "DOCUMENT_ROOT",               &zHome },
   359	  { "HTTP_ACCEPT",                 &zAccept },
   360	  { "HTTP_ACCEPT_ENCODING",        &zAcceptEncoding },
   361	  { "HTTP_COOKIE",                 &zCookie },
   362	  { "HTTP_HOST",                   &zHttpHost },
   363	  { "HTTP_IF_MODIFIED_SINCE",      &zIfModifiedSince },
   364	  { "HTTP_IF_NONE_MATCH",          &zIfNoneMatch },
   365	  { "HTTP_REFERER",                &zReferer },
   366	  { "HTTP_USER_AGENT",             &zAgent },
   367	  { "PATH",                        &default_path },
   368	  { "PATH_INFO",                   &zPathInfo },
   369	  { "QUERY_STRING",                &zQueryString },
   370	  { "REMOTE_ADDR",                 &zRemoteAddr },
   371	  { "REQUEST_METHOD",              &zMethod },
   372	  { "REQUEST_URI",                 &zScript },
   373	  { "REMOTE_USER",                 &zRemoteUser },
   374	  { "SCGI",                        &zScgi },
   375	  { "SCRIPT_DIRECTORY",            &zDir },
   376	  { "SCRIPT_FILENAME",             &zFile },
   377	  { "SCRIPT_NAME",                 &zRealScript },
   378	  { "SERVER_NAME",                 &zServerName },
   379	  { "SERVER_PORT",                 &zServerPort },
   380	  { "SERVER_PROTOCOL",             &zProtocol },
   381	};
   382	
   383	
   384	/*
   385	** Double any double-quote characters in a string.
   386	*/
   387	static char *Escape(char *z){
   388	  size_t i, j;
   389	  size_t n;
   390	  char c;
   391	  char *zOut;
   392	  for(i=0; (c=z[i])!=0 && c!='"'; i++){}
   393	  if( c==0 ) return z;
   394	  n = 1;
   395	  for(i++; (c=z[i])!=0; i++){ if( c=='"' ) n++; }
   396	  zOut = malloc( i+n+1 );
   397	  if( zOut==0 ) return "";
   398	  for(i=j=0; (c=z[i])!=0; i++){
   399	    zOut[j++] = c;
   400	    if( c=='"' ) zOut[j++] = c;
   401	  }
   402	  zOut[j] = 0;
   403	  return zOut;
   404	}
   405	
   406	/*
   407	** Convert a struct timeval into an integer number of microseconds
   408	*/
   409	static long long int tvms(struct timeval *p){
   410	  return ((long long int)p->tv_sec)*1000000 + (long long int)p->tv_usec;
   411	}
   412	
   413	/*
   414	** Make an entry in the log file.  If the HTTP connection should be
   415	** closed, then terminate this process.  Otherwise return.
   416	*/
   417	static void MakeLogEntry(int exitCode, int lineNum){
   418	  FILE *log;
   419	  if( zTmpNam ){
   420	    unlink(zTmpNam);
   421	  }
   422	  if( zLogFile && !omitLog ){
   423	    struct timeval now;
   424	    struct tm *pTm;
   425	    struct rusage self, children;
   426	    int waitStatus;
   427	    char *zRM = zRemoteUser ? zRemoteUser : "";
   428	    char *zFilename;
   429	    size_t sz;
   430	    char zDate[200];
   431	    char zExpLogFile[500];
   432	
   433	    if( zScript==0 ) zScript = "";
   434	    if( zRealScript==0 ) zRealScript = "";
   435	    if( zRemoteAddr==0 ) zRemoteAddr = "";
   436	    if( zHttpHost==0 ) zHttpHost = "";
   437	    if( zReferer==0 ) zReferer = "";
   438	    if( zAgent==0 ) zAgent = "";
   439	    gettimeofday(&now, 0);
   440	    pTm = localtime(&now.tv_sec);
   441	    strftime(zDate, sizeof(zDate), "%Y-%m-%d %H:%M:%S", pTm);
   442	    sz = strftime(zExpLogFile, sizeof(zExpLogFile), zLogFile, pTm);
   443	    if( sz>0 && sz<sizeof(zExpLogFile)-2 ){
   444	      zFilename = zExpLogFile;
   445	    }else{
   446	      zFilename = zLogFile;
   447	    }
   448	    waitpid(-1, &waitStatus, WNOHANG);
   449	    getrusage(RUSAGE_SELF, &self);
   450	    getrusage(RUSAGE_CHILDREN, &children);
   451	    if( (log = fopen(zFilename,"a"))!=0 ){
   452	#ifdef COMBINED_LOG_FORMAT
   453	      strftime(zDate, sizeof(zDate), "%d/%b/%Y:%H:%M:%S %Z", pTm);
   454	      fprintf(log, "%s - - [%s] \"%s %s %s\" %s %d \"%s\" \"%s\"\n",
   455	              zRemoteAddr, zDate, zMethod, zScript, zProtocol,
   456	              zReplyStatus, nOut, zReferer, zAgent);
   457	#else
   458	      strftime(zDate, sizeof(zDate), "%Y-%m-%d %H:%M:%S", pTm);
   459	      /* Log record files:
   460	      **  (1) Date and time
   461	      **  (2) IP address
   462	      **  (3) URL being accessed
   463	      **  (4) Referer
   464	      **  (5) Reply status
   465	      **  (6) Bytes received
   466	      **  (7) Bytes sent
   467	      **  (8) Self user time
   468	      **  (9) Self system time
   469	      ** (10) Children user time
   470	      ** (11) Children system time
   471	      ** (12) Total wall-clock time
   472	      ** (13) Request number for same TCP/IP connection
   473	      ** (14) User agent
   474	      ** (15) Remote user
   475	      ** (16) Bytes of URL that correspond to the SCRIPT_NAME
   476	      ** (17) Line number in source file
   477	      */
   478	      fprintf(log,
   479	        "%s,%s,\"%s://%s%s\",\"%s\","
   480	           "%s,%d,%d,%lld,%lld,%lld,%lld,%lld,%d,\"%s\",\"%s\",%d,%d\n",
   481	        zDate, zRemoteAddr, zHttp, Escape(zHttpHost), Escape(zScript),
   482	        Escape(zReferer), zReplyStatus, nIn, nOut,
   483	        tvms(&self.ru_utime) - tvms(&priorSelf.ru_utime),
   484	        tvms(&self.ru_stime) - tvms(&priorSelf.ru_stime),
   485	        tvms(&children.ru_utime) - tvms(&priorChild.ru_utime),
   486	        tvms(&children.ru_stime) - tvms(&priorChild.ru_stime),
   487	        tvms(&now) - tvms(&beginTime),
   488	        nRequest, Escape(zAgent), Escape(zRM),
   489	        (int)(strlen(zHttp)+strlen(zHttpHost)+strlen(zRealScript)+3),
   490	        lineNum
   491	      );
   492	      priorSelf = self;
   493	      priorChild = children;
   494	#endif
   495	      fclose(log);
   496	      nIn = nOut = 0;
   497	    }
   498	  }
   499	  if( closeConnection ){
   500	    exit(exitCode);
   501	  }
   502	  statusSent = 0;
   503	}
   504	
   505	/*
   506	** Allocate memory safely
   507	*/
   508	static char *SafeMalloc( size_t size ){
   509	  char *p;
   510	
   511	  p = (char*)malloc(size);
   512	  if( p==0 ){
   513	    strcpy(zReplyStatus, "998");
   514	    MakeLogEntry(1,100);  /* LOG: Malloc() failed */
   515	    exit(1);
   516	  }
   517	  return p;
   518	}
   519	
   520	/*
   521	** Set the value of environment variable zVar to zValue.
   522	*/
   523	static void SetEnv(const char *zVar, const char *zValue){
   524	  char *z;
   525	  size_t len;
   526	  if( zValue==0 ) zValue="";
   527	  /* Disable an attempted bashdoor attack */
   528	  if( strncmp(zValue,"() {",4)==0 ) zValue = "";
   529	  len = strlen(zVar) + strlen(zValue) + 2;
   530	  z = SafeMalloc(len);
   531	  sprintf(z,"%s=%s",zVar,zValue);
   532	  putenv(z);
   533	}
   534	
   535	/*
   536	** Remove the first space-delimited token from a string and return
   537	** a pointer to it.  Add a NULL to the string to terminate the token.
   538	** Make *zLeftOver point to the start of the next token.
   539	*/
   540	static char *GetFirstElement(char *zInput, char **zLeftOver){
   541	  char *zResult = 0;
   542	  if( zInput==0 ){
   543	    if( zLeftOver ) *zLeftOver = 0;
   544	    return 0;
   545	  }
   546	  while( isspace(*(unsigned char*)zInput) ){ zInput++; }
   547	  zResult = zInput;
   548	  while( *zInput && !isspace(*(unsigned char*)zInput) ){ zInput++; }
   549	  if( *zInput ){
   550	    *zInput = 0;
   551	    zInput++;
   552	    while( isspace(*(unsigned char*)zInput) ){ zInput++; }
   553	  }
   554	  if( zLeftOver ){ *zLeftOver = zInput; }
   555	  return zResult;
   556	}
   557	
   558	/*
   559	** Make a copy of a string into memory obtained from malloc.
   560	*/
   561	static char *StrDup(const char *zSrc){
   562	  char *zDest;
   563	  size_t size;
   564	
   565	  if( zSrc==0 ) return 0;
   566	  size = strlen(zSrc) + 1;
   567	  zDest = (char*)SafeMalloc( size );
   568	  strcpy(zDest,zSrc);
   569	  return zDest;
   570	}
   571	static char *StrAppend(char *zPrior, const char *zSep, const char *zSrc){
   572	  char *zDest;
   573	  size_t size;
   574	  size_t n0, n1, n2;
   575	
   576	  if( zSrc==0 ) return 0;
   577	  if( zPrior==0 ) return StrDup(zSrc);
   578	  n0 = strlen(zPrior);
   579	  n1 = strlen(zSep);
   580	  n2 = strlen(zSrc);
   581	  size = n0+n1+n2+1;
   582	  zDest = (char*)SafeMalloc( size );
   583	  memcpy(zDest, zPrior, n0);
   584	  free(zPrior);
   585	  memcpy(&zDest[n0],zSep,n1);
   586	  memcpy(&zDest[n0+n1],zSrc,n2+1);
   587	  return zDest;
   588	}
   589	
   590	/*
   591	** Compare two ETag values. Return 0 if they match and non-zero if they differ.
   592	**
   593	** The one on the left might be a NULL pointer and it might be quoted.
   594	*/
   595	static int CompareEtags(const char *zA, const char *zB){
   596	  if( zA==0 ) return 1;
   597	  if( zA[0]=='"' ){
   598	    int lenB = (int)strlen(zB);
   599	    if( strncmp(zA+1, zB, lenB)==0 && zA[lenB+1]=='"' ) return 0;
   600	  }
   601	  return strcmp(zA, zB);
   602	}
   603	
   604	/*
   605	** Break a line at the first \n or \r character seen.
   606	*/
   607	static void RemoveNewline(char *z){
   608	  if( z==0 ) return;
   609	  while( *z && *z!='\n' && *z!='\r' ){ z++; }
   610	  *z = 0;
   611	}
   612	
   613	/* Render seconds since 1970 as an RFC822 date string.  Return
   614	** a pointer to that string in a static buffer.
   615	*/
   616	static char *Rfc822Date(time_t t){
   617	  struct tm *tm;
   618	  static char zDate[100];
   619	  tm = gmtime(&t);
   620	  strftime(zDate, sizeof(zDate), "%a, %d %b %Y %H:%M:%S %Z", tm);
   621	  return zDate;
   622	}
   623	
   624	/*
   625	** Print a date tag in the header.  The name of the tag is zTag.
   626	** The date is determined from the unix timestamp given.
   627	*/
   628	static int DateTag(const char *zTag, time_t t){
   629	  return printf("%s: %s\r\n", zTag, Rfc822Date(t));
   630	}
   631	
   632	/*
   633	** Parse an RFC822-formatted timestamp as we'd expect from HTTP and return
   634	** a Unix epoch time. <= zero is returned on failure.
   635	*/
   636	time_t ParseRfc822Date(const char *zDate){
   637	  int mday, mon, year, yday, hour, min, sec;
   638	  char zIgnore[4];
   639	  char zMonth[4];
   640	  static const char *const azMonths[] =
   641	    {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
   642	     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
   643	  if( 7==sscanf(zDate, "%3[A-Za-z], %d %3[A-Za-z] %d %d:%d:%d", zIgnore,
   644	                       &mday, zMonth, &year, &hour, &min, &sec)){
   645	    if( year > 1900 ) year -= 1900;
   646	    for(mon=0; mon<12; mon++){
   647	      if( !strncmp( azMonths[mon], zMonth, 3 )){
   648	        int nDay;
   649	        int isLeapYr;
   650	        static int priorDays[] =
   651	         {  0, 31, 59, 90,120,151,181,212,243,273,304,334 };
   652	        isLeapYr = year%4==0 && (year%100!=0 || (year+300)%400==0);
   653	        yday = priorDays[mon] + mday - 1;
   654	        if( isLeapYr && mon>1 ) yday++;
   655	        nDay = (year-70)*365 + (year-69)/4 - year/100 + (year+300)/400 + yday;
   656	        return ((time_t)(nDay*24 + hour)*60 + min)*60 + sec;
   657	      }
   658	    }
   659	  }
   660	  return 0;
   661	}
   662	
   663	/*
   664	** Test procedure for ParseRfc822Date
   665	*/
   666	void TestParseRfc822Date(void){
   667	  time_t t1, t2;
   668	  for(t1=0; t1<0x7fffffff; t1 += 127){
   669	    t2 = ParseRfc822Date(Rfc822Date(t1));
   670	    assert( t1==t2 );
   671	  }
   672	}
   673	
   674	/*
   675	** Print the first line of a response followed by the server type.
   676	*/
   677	static void StartResponse(const char *zResultCode){
   678	  time_t now;
   679	  time(&now);
   680	  if( statusSent ) return;
   681	  nOut += printf("%s %s\r\n", zProtocol, zResultCode);
   682	  strncpy(zReplyStatus, zResultCode, 3);
   683	  zReplyStatus[3] = 0;
   684	  if( zReplyStatus[0]>='4' ){
   685	    closeConnection = 1;
   686	  }
   687	  if( closeConnection ){
   688	    nOut += printf("Connection: close\r\n");
   689	  }else{
   690	    nOut += printf("Connection: keep-alive\r\n");
   691	  }
   692	  nOut += DateTag("Date", now);
   693	  statusSent = 1;
   694	}
   695	
   696	/*
   697	** Tell the client that there is no such document
   698	*/
   699	static void NotFound(int lineno){
   700	  StartResponse("404 Not Found");
   701	  nOut += printf(
   702	    "Content-type: text/html; charset=utf-8\r\n"
   703	    "\r\n"
   704	    "<head><title lineno=\"%d\">Not Found</title></head>\n"
   705	    "<body><h1>Document Not Found</h1>\n"
   706	    "The document %s is not available on this server\n"
   707	    "</body>\n", lineno, zScript);
   708	  MakeLogEntry(0, lineno);
   709	  exit(0);
   710	}
   711	
   712	/*
   713	** Tell the client that they are not welcomed here.
   714	*/
   715	static void Forbidden(int lineno){
   716	  StartResponse("403 Forbidden");
   717	  nOut += printf(
   718	    "Content-type: text/plain; charset=utf-8\r\n"
   719	    "\r\n"
   720	    "Access denied\n"
   721	  );
   722	  closeConnection = 1;
   723	  MakeLogEntry(0, lineno);
   724	  exit(0);
   725	}
   726	
   727	/*
   728	** Tell the client that authorization is required to access the
   729	** document.
   730	*/
   731	static void NotAuthorized(const char *zRealm){
   732	  StartResponse("401 Authorization Required");
   733	  nOut += printf(
   734	    "WWW-Authenticate: Basic realm=\"%s\"\r\n"
   735	    "Content-type: text/html; charset=utf-8\r\n"
   736	    "\r\n"
   737	    "<head><title>Not Authorized</title></head>\n"
   738	    "<body><h1>401 Not Authorized</h1>\n"
   739	    "A login and password are required for this document\n"
   740	    "</body>\n", zRealm);
   741	  MakeLogEntry(0, 110);  /* LOG: Not authorized */
   742	}
   743	
   744	/*
   745	** Tell the client that there is an error in the script.
   746	*/
   747	static void CgiError(void){
   748	  StartResponse("500 Error");
   749	  nOut += printf(
   750	    "Content-type: text/html; charset=utf-8\r\n"
   751	    "\r\n"
   752	    "<head><title>CGI Program Error</title></head>\n"
   753	    "<body><h1>CGI Program Error</h1>\n"
   754	    "The CGI program %s generated an error\n"
   755	    "</body>\n", zScript);
   756	  MakeLogEntry(0, 120);  /* LOG: CGI Error */
   757	  exit(0);
   758	}
   759	
   760	/*
   761	** This is called if we timeout or catch some other kind of signal.
   762	** Log an error code which is 900+iSig and then quit.
   763	*/
   764	static void Timeout(int iSig){
   765	  if( !debugFlag ){
   766	    if( zScript && zScript[0] ){
   767	      char zBuf[10];
   768	      zBuf[0] = '9';
   769	      zBuf[1] = '0' + (iSig/10)%10;
   770	      zBuf[2] = '0' + iSig%10;
   771	      zBuf[3] = 0;
   772	      strcpy(zReplyStatus, zBuf);
   773	      MakeLogEntry(0, 130);  /* LOG: Timeout */
   774	    }
   775	    exit(0);
   776	  }
   777	}
   778	
   779	/*
   780	** Tell the client that there is an error in the script.
   781	*/
   782	static void CgiScriptWritable(void){
   783	  StartResponse("500 CGI Configuration Error");
   784	  nOut += printf(
   785	    "Content-type: text/plain; charset=utf-8\r\n"
   786	    "\r\n"
   787	    "The CGI program %s is writable by users other than its owner.\n",
   788	    zRealScript);
   789	  MakeLogEntry(0, 140);  /* LOG: CGI script is writable */
   790	  exit(0);       
   791	}
   792	
   793	/*
   794	** Tell the client that the server malfunctioned.
   795	*/
   796	static void Malfunction(int linenum, const char *zFormat, ...){
   797	  va_list ap;
   798	  va_start(ap, zFormat);
   799	  StartResponse("500 Server Malfunction");
   800	  nOut += printf(
   801	    "Content-type: text/plain; charset=utf-8\r\n"
   802	    "\r\n"
   803	    "Web server malfunctioned; error number %d\n\n", linenum);
   804	  if( zFormat ){
   805	    nOut += vprintf(zFormat, ap);
   806	    printf("\n");
   807	    nOut++;
   808	  }
   809	  va_end(ap);
   810	  MakeLogEntry(0, linenum);
   811	  exit(0);
   812	}
   813	
   814	/*
   815	** Do a server redirect to the document specified.  The document
   816	** name not contain scheme or network location or the query string.
   817	** It will be just the path.
   818	*/
   819	static void Redirect(const char *zPath, int iStatus, int finish, int lineno){
   820	  switch( iStatus ){
   821	    case 301:
   822	      StartResponse("301 Permanent Redirect");
   823	      break;
   824	    case 308:
   825	      StartResponse("308 Permanent Redirect");
   826	      break;
   827	    default:
   828	      StartResponse("302 Temporary Redirect");
   829	      break;
   830	  }
   831	  if( zServerPort==0 || zServerPort[0]==0 || strcmp(zServerPort,"80")==0 ){
   832	    nOut += printf("Location: %s://%s%s%s\r\n",
   833	                   zHttp, zServerName, zPath, zQuerySuffix);
   834	  }else{
   835	    nOut += printf("Location: %s://%s:%s%s%s\r\n",
   836	                   zHttp, zServerName, zServerPort, zPath, zQuerySuffix);
   837	  }
   838	  if( finish ){
   839	    nOut += printf("Content-length: 0\r\n");
   840	    nOut += printf("\r\n");
   841	    MakeLogEntry(0, lineno);
   842	  }
   843	  fflush(stdout);
   844	}
   845	
   846	/*
   847	** This function treats its input as a base-64 string and returns the
   848	** decoded value of that string.  Characters of input that are not
   849	** valid base-64 characters (such as spaces and newlines) are ignored.
   850	*/
   851	void Decode64(char *z64){
   852	  char *zData;
   853	  int n64;
   854	  int i, j;
   855	  int a, b, c, d;
   856	  static int isInit = 0;
   857	  static int trans[128];
   858	  static unsigned char zBase[] = 
   859	    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
   860	
   861	  if( !isInit ){
   862	    for(i=0; i<128; i++){ trans[i] = 0; }
   863	    for(i=0; zBase[i]; i++){ trans[zBase[i] & 0x7f] = i; }
   864	    isInit = 1;
   865	  }
   866	  n64 = strlen(z64);
   867	  while( n64>0 && z64[n64-1]=='=' ) n64--;
   868	  zData = z64;
   869	  for(i=j=0; i+3<n64; i+=4){
   870	    a = trans[z64[i] & 0x7f];
   871	    b = trans[z64[i+1] & 0x7f];
   872	    c = trans[z64[i+2] & 0x7f];
   873	    d = trans[z64[i+3] & 0x7f];
   874	    zData[j++] = ((a<<2) & 0xfc) | ((b>>4) & 0x03);
   875	    zData[j++] = ((b<<4) & 0xf0) | ((c>>2) & 0x0f);
   876	    zData[j++] = ((c<<6) & 0xc0) | (d & 0x3f);
   877	  }
   878	  if( i+2<n64 ){
   879	    a = trans[z64[i] & 0x7f];
   880	    b = trans[z64[i+1] & 0x7f];
   881	    c = trans[z64[i+2] & 0x7f];
   882	    zData[j++] = ((a<<2) & 0xfc) | ((b>>4) & 0x03);
   883	    zData[j++] = ((b<<4) & 0xf0) | ((c>>2) & 0x0f);
   884	  }else if( i+1<n64 ){
   885	    a = trans[z64[i] & 0x7f];
   886	    b = trans[z64[i+1] & 0x7f];
   887	    zData[j++] = ((a<<2) & 0xfc) | ((b>>4) & 0x03);
   888	  }
   889	  zData[j] = 0;
   890	}
   891	
   892	/*
   893	** Check to see if basic authorization credentials are provided for
   894	** the user according to the information in zAuthFile.  Return true
   895	** if authorized.  Return false if not authorized.
   896	**
   897	** File format:
   898	**
   899	**    *  Blank lines and lines that begin with '#' are ignored
   900	**    *  "http-redirect" forces a redirect to HTTPS if not there already
   901	**    *  "https-only" disallows operation in HTTP
   902	**    *  "user NAME LOGIN:PASSWORD" checks to see if LOGIN:PASSWORD 
   903	**       authorization credentials are provided, and if so sets the
   904	**       REMOTE_USER to NAME.
   905	**    *  "realm TEXT" sets the realm to TEXT.
   906	**    *  "anyone" bypasses authentication and allows anyone to see the
   907	**       files.  Useful in combination with "http-redirect"
   908	*/
   909	static int CheckBasicAuthorization(const char *zAuthFile){
   910	  FILE *in;
   911	  char *zRealm = "unknown realm";
   912	  char *zLoginPswd;
   913	  char *zName;
   914	  char zLine[2000];
   915	
   916	  in = fopen(zAuthFile, "rb");
   917	  if( in==0 ){
   918	    NotFound(150);  /* LOG: Cannot open -auth file */
   919	    return 0;
   920	  }
   921	  if( zAuthArg ) Decode64(zAuthArg);
   922	  while( fgets(zLine, sizeof(zLine), in) ){
   923	    char *zFieldName;
   924	    char *zVal;
   925	
   926	    zFieldName = GetFirstElement(zLine,&zVal);
   927	    if( zFieldName==0 || *zFieldName==0 ) continue;
   928	    if( zFieldName[0]=='#' ) continue;
   929	    RemoveNewline(zVal);
   930	    if( strcmp(zFieldName, "realm")==0 ){
   931	      zRealm = StrDup(zVal);
   932	    }else if( strcmp(zFieldName,"user")==0 ){
   933	      if( zAuthArg==0 ) continue;
   934	      zName = GetFirstElement(zVal, &zVal);
   935	      zLoginPswd = GetFirstElement(zVal, &zVal);
   936	      if( zLoginPswd==0 ) continue;
   937	      if( zAuthArg && strcmp(zAuthArg,zLoginPswd)==0 ){
   938	        zRemoteUser = StrDup(zName);
   939	        fclose(in);
   940	        return 1;
   941	      }
   942	    }else if( strcmp(zFieldName,"https-only")==0 ){
   943	      if( !useHttps ){
   944	        NotFound(160);  /* LOG:  http request on https-only page */
   945	        fclose(in);
   946	        return 0;
   947	      }
   948	    }else if( strcmp(zFieldName,"http-redirect")==0 ){
   949	      if( !useHttps ){
   950	        zHttp = "https";
   951	        Redirect(zScript, 301, 1, 170); /* LOG: -auth redirect */
   952	        fclose(in);
   953	        return 0;
   954	      }
   955	    }else if( strcmp(zFieldName,"anyone")==0 ){
   956	      fclose(in);
   957	      return 1;
   958	    }else{
   959	      NotFound(180);  /* LOG:  malformed entry in -auth file */
   960	      fclose(in);
   961	      return 0;
   962	    }
   963	  }
   964	  fclose(in);
   965	  NotAuthorized(zRealm);
   966	  return 0;
   967	}
   968	
   969	/*
   970	** Guess the mime-type of a document based on its name.
   971	*/
   972	const char *GetMimeType(const char *zName, int nName){
   973	  const char *z;
   974	  int i;
   975	  int first, last;
   976	  int len;
   977	  char zSuffix[20];
   978	
   979	  /* A table of mimetypes based on file suffixes. 
   980	  ** Suffixes must be in sorted order so that we can do a binary
   981	  ** search to find the mime-type
   982	  */
   983	  static const struct {
   984	    const char *zSuffix;       /* The file suffix */
   985	    int size;                  /* Length of the suffix */
   986	    const char *zMimetype;     /* The corresponding mimetype */
   987	  } aMime[] = {
   988	    { "ai",         2, "application/postscript"            },
   989	    { "aif",        3, "audio/x-aiff"                      },
   990	    { "aifc",       4, "audio/x-aiff"                      },
   991	    { "aiff",       4, "audio/x-aiff"                      },
   992	    { "arj",        3, "application/x-arj-compressed"      },
   993	    { "asc",        3, "text/plain"                        },
   994	    { "asf",        3, "video/x-ms-asf"                    },
   995	    { "asx",        3, "video/x-ms-asx"                    },
   996	    { "au",         2, "audio/ulaw"                        },
   997	    { "avi",        3, "video/x-msvideo"                   },
   998	    { "bat",        3, "application/x-msdos-program"       },
   999	    { "bcpio",      5, "application/x-bcpio"               },
  1000	    { "bin",        3, "application/octet-stream"          },
  1001	    { "c",          1, "text/plain"                        },
  1002	    { "cc",         2, "text/plain"                        },
  1003	    { "ccad",       4, "application/clariscad"             },
  1004	    { "cdf",        3, "application/x-netcdf"              },
  1005	    { "class",      5, "application/octet-stream"          },
  1006	    { "cod",        3, "application/vnd.rim.cod"           },
  1007	    { "com",        3, "application/x-msdos-program"       },
  1008	    { "cpio",       4, "application/x-cpio"                },
  1009	    { "cpt",        3, "application/mac-compactpro"        },
  1010	    { "csh",        3, "application/x-csh"                 },
  1011	    { "css",        3, "text/css"                          },
  1012	    { "dcr",        3, "application/x-director"            },
  1013	    { "deb",        3, "application/x-debian-package"      },
  1014	    { "dir",        3, "application/x-director"            },
  1015	    { "dl",         2, "video/dl"                          },
  1016	    { "dms",        3, "application/octet-stream"          },
  1017	    { "doc",        3, "application/msword"                },
  1018	    { "drw",        3, "application/drafting"              },
  1019	    { "dvi",        3, "application/x-dvi"                 },
  1020	    { "dwg",        3, "application/acad"                  },
  1021	    { "dxf",        3, "application/dxf"                   },
  1022	    { "dxr",        3, "application/x-director"            },
  1023	    { "eps",        3, "application/postscript"            },
  1024	    { "etx",        3, "text/x-setext"                     },
  1025	    { "exe",        3, "application/octet-stream"          },
  1026	    { "ez",         2, "application/andrew-inset"          },
  1027	    { "f",          1, "text/plain"                        },
  1028	    { "f90",        3, "text/plain"                        },
  1029	    { "fli",        3, "video/fli"                         },
  1030	    { "flv",        3, "video/flv"                         },
  1031	    { "gif",        3, "image/gif"                         },
  1032	    { "gl",         2, "video/gl"                          },
  1033	    { "gtar",       4, "application/x-gtar"                },
  1034	    { "gz",         2, "application/x-gzip"                },
  1035	    { "hdf",        3, "application/x-hdf"                 },
  1036	    { "hh",         2, "text/plain"                        },
  1037	    { "hqx",        3, "application/mac-binhex40"          },
  1038	    { "h",          1, "text/plain"                        },
  1039	    { "htm",        3, "text/html; charset=utf-8"          },
  1040	    { "html",       4, "text/html; charset=utf-8"          },
  1041	    { "ice",        3, "x-conference/x-cooltalk"           },
  1042	    { "ief",        3, "image/ief"                         },
  1043	    { "iges",       4, "model/iges"                        },
  1044	    { "igs",        3, "model/iges"                        },
  1045	    { "ips",        3, "application/x-ipscript"            },
  1046	    { "ipx",        3, "application/x-ipix"                },
  1047	    { "jad",        3, "text/vnd.sun.j2me.app-descriptor"  },
  1048	    { "jar",        3, "application/java-archive"          },
  1049	    { "jpeg",       4, "image/jpeg"                        },
  1050	    { "jpe",        3, "image/jpeg"                        },
  1051	    { "jpg",        3, "image/jpeg"                        },
  1052	    { "js",         2, "application/x-javascript"          },
  1053	    { "kar",        3, "audio/midi"                        },
  1054	    { "latex",      5, "application/x-latex"               },
  1055	    { "lha",        3, "application/octet-stream"          },
  1056	    { "lsp",        3, "application/x-lisp"                },
  1057	    { "lzh",        3, "application/octet-stream"          },
  1058	    { "m",          1, "text/plain"                        },
  1059	    { "m3u",        3, "audio/x-mpegurl"                   },
  1060	    { "man",        3, "application/x-troff-man"           },
  1061	    { "me",         2, "application/x-troff-me"            },
  1062	    { "mesh",       4, "model/mesh"                        },
  1063	    { "mid",        3, "audio/midi"                        },
  1064	    { "midi",       4, "audio/midi"                        },
  1065	    { "mif",        3, "application/x-mif"                 },
  1066	    { "mime",       4, "www/mime"                          },
  1067	    { "movie",      5, "video/x-sgi-movie"                 },
  1068	    { "mov",        3, "video/quicktime"                   },
  1069	    { "mp2",        3, "audio/mpeg"                        },
  1070	    { "mp2",        3, "video/mpeg"                        },
  1071	    { "mp3",        3, "audio/mpeg"                        },
  1072	    { "mpeg",       4, "video/mpeg"                        },
  1073	    { "mpe",        3, "video/mpeg"                        },
  1074	    { "mpga",       4, "audio/mpeg"                        },
  1075	    { "mpg",        3, "video/mpeg"                        },
  1076	    { "ms",         2, "application/x-troff-ms"            },
  1077	    { "msh",        3, "model/mesh"                        },
  1078	    { "nc",         2, "application/x-netcdf"              },
  1079	    { "oda",        3, "application/oda"                   },
  1080	    { "ogg",        3, "application/ogg"                   },
  1081	    { "ogm",        3, "application/ogg"                   },
  1082	    { "pbm",        3, "image/x-portable-bitmap"           },
  1083	    { "pdb",        3, "chemical/x-pdb"                    },
  1084	    { "pdf",        3, "application/pdf"                   },
  1085	    { "pgm",        3, "image/x-portable-graymap"          },
  1086	    { "pgn",        3, "application/x-chess-pgn"           },
  1087	    { "pgp",        3, "application/pgp"                   },
  1088	    { "pl",         2, "application/x-perl"                },
  1089	    { "pm",         2, "application/x-perl"                },
  1090	    { "png",        3, "image/png"                         },
  1091	    { "pnm",        3, "image/x-portable-anymap"           },
  1092	    { "pot",        3, "application/mspowerpoint"          },
  1093	    { "ppm",        3, "image/x-portable-pixmap"           },
  1094	    { "pps",        3, "application/mspowerpoint"          },
  1095	    { "ppt",        3, "application/mspowerpoint"          },
  1096	    { "ppz",        3, "application/mspowerpoint"          },
  1097	    { "pre",        3, "application/x-freelance"           },
  1098	    { "prt",        3, "application/pro_eng"               },
  1099	    { "ps",         2, "application/postscript"            },
  1100	    { "qt",         2, "video/quicktime"                   },
  1101	    { "ra",         2, "audio/x-realaudio"                 },
  1102	    { "ram",        3, "audio/x-pn-realaudio"              },
  1103	    { "rar",        3, "application/x-rar-compressed"      },
  1104	    { "ras",        3, "image/cmu-raster"                  },
  1105	    { "ras",        3, "image/x-cmu-raster"                },
  1106	    { "rgb",        3, "image/x-rgb"                       },
  1107	    { "rm",         2, "audio/x-pn-realaudio"              },
  1108	    { "roff",       4, "application/x-troff"               },
  1109	    { "rpm",        3, "audio/x-pn-realaudio-plugin"       },
  1110	    { "rtf",        3, "application/rtf"                   },
  1111	    { "rtf",        3, "text/rtf"                          },
  1112	    { "rtx",        3, "text/richtext"                     },
  1113	    { "scm",        3, "application/x-lotusscreencam"      },
  1114	    { "set",        3, "application/set"                   },
  1115	    { "sgml",       4, "text/sgml"                         },
  1116	    { "sgm",        3, "text/sgml"                         },
  1117	    { "sh",         2, "application/x-sh"                  },
  1118	    { "shar",       4, "application/x-shar"                },
  1119	    { "silo",       4, "model/mesh"                        },
  1120	    { "sit",        3, "application/x-stuffit"             },
  1121	    { "skd",        3, "application/x-koan"                },
  1122	    { "skm",        3, "application/x-koan"                },
  1123	    { "skp",        3, "application/x-koan"                },
  1124	    { "skt",        3, "application/x-koan"                },
  1125	    { "smi",        3, "application/smil"                  },
  1126	    { "smil",       4, "application/smil"                  },
  1127	    { "snd",        3, "audio/basic"                       },
  1128	    { "sol",        3, "application/solids"                },
  1129	    { "spl",        3, "application/x-futuresplash"        },
  1130	    { "src",        3, "application/x-wais-source"         },
  1131	    { "step",       4, "application/STEP"                  },
  1132	    { "stl",        3, "application/SLA"                   },
  1133	    { "stp",        3, "application/STEP"                  },
  1134	    { "sv4cpio",    7, "application/x-sv4cpio"             },
  1135	    { "sv4crc",     6, "application/x-sv4crc"              },
  1136	    { "svg",        3, "image/svg+xml"                     },
  1137	    { "swf",        3, "application/x-shockwave-flash"     },
  1138	    { "t",          1, "application/x-troff"               },
  1139	    { "tar",        3, "application/x-tar"                 },
  1140	    { "tcl",        3, "application/x-tcl"                 },
  1141	    { "tex",        3, "application/x-tex"                 },
  1142	    { "texi",       4, "application/x-texinfo"             },
  1143	    { "texinfo",    7, "application/x-texinfo"             },
  1144	    { "tgz",        3, "application/x-tar-gz"              },
  1145	    { "tiff",       4, "image/tiff"                        },
  1146	    { "tif",        3, "image/tiff"                        },
  1147	    { "tr",         2, "application/x-troff"               },
  1148	    { "tsi",        3, "audio/TSP-audio"                   },
  1149	    { "tsp",        3, "application/dsptype"               },
  1150	    { "tsv",        3, "text/tab-separated-values"         },
  1151	    { "txt",        3, "text/plain"                        },
  1152	    { "unv",        3, "application/i-deas"                },
  1153	    { "ustar",      5, "application/x-ustar"               },
  1154	    { "vcd",        3, "application/x-cdlink"              },
  1155	    { "vda",        3, "application/vda"                   },
  1156	    { "viv",        3, "video/vnd.vivo"                    },
  1157	    { "vivo",       4, "video/vnd.vivo"                    },
  1158	    { "vrml",       4, "model/vrml"                        },
  1159	    { "vsix",       4, "application/vsix"                  },
  1160	    { "wav",        3, "audio/x-wav"                       },
  1161	    { "wax",        3, "audio/x-ms-wax"                    },
  1162	    { "wiki",       4, "application/x-fossil-wiki"         },
  1163	    { "wma",        3, "audio/x-ms-wma"                    },
  1164	    { "wmv",        3, "video/x-ms-wmv"                    },
  1165	    { "wmx",        3, "video/x-ms-wmx"                    },
  1166	    { "wrl",        3, "model/vrml"                        },
  1167	    { "wvx",        3, "video/x-ms-wvx"                    },
  1168	    { "xbm",        3, "image/x-xbitmap"                   },
  1169	    { "xlc",        3, "application/vnd.ms-excel"          },
  1170	    { "xll",        3, "application/vnd.ms-excel"          },
  1171	    { "xlm",        3, "application/vnd.ms-excel"          },
  1172	    { "xls",        3, "application/vnd.ms-excel"          },
  1173	    { "xlw",        3, "application/vnd.ms-excel"          },
  1174	    { "xml",        3, "text/xml"                          },
  1175	    { "xpm",        3, "image/x-xpixmap"                   },
  1176	    { "xwd",        3, "image/x-xwindowdump"               },
  1177	    { "xyz",        3, "chemical/x-pdb"                    },
  1178	    { "zip",        3, "application/zip"                   },
  1179	  };
  1180	
  1181	  for(i=nName-1; i>0 && zName[i]!='.'; i--){}
  1182	  z = &zName[i+1];
  1183	  len = nName - i;
  1184	  if( len<(int)sizeof(zSuffix)-1 ){
  1185	    strcpy(zSuffix, z);
  1186	    for(i=0; zSuffix[i]; i++) zSuffix[i] = tolower(zSuffix[i]);
  1187	    first = 0;
  1188	    last = sizeof(aMime)/sizeof(aMime[0]);
  1189	    while( first<=last ){
  1190	      int c;
  1191	      i = (first+last)/2;
  1192	      c = strcmp(zSuffix, aMime[i].zSuffix);
  1193	      if( c==0 ) return aMime[i].zMimetype;
  1194	      if( c<0 ){
  1195	        last = i-1;
  1196	      }else{
  1197	        first = i+1;
  1198	      }
  1199	    }
  1200	  }
  1201	  return "application/octet-stream";
  1202	}
  1203	
  1204	/*
  1205	** The following table contains 1 for all characters that are permitted in
  1206	** the part of the URL before the query parameters and fragment.
  1207	**
  1208	** Allowed characters:  0-9a-zA-Z,-./:_~
  1209	**
  1210	** Disallowed characters include:  !"#$%&'()*+;<=>?[\]^{|}
  1211	*/
  1212	static const char allowedInName[] = {
  1213	      /*  x0  x1  x2  x3  x4  x5  x6  x7  x8  x9  xa  xb  xc  xd  xe  xf */
  1214	/* 0x */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
  1215	/* 1x */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
  1216	/* 2x */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  1,  1,  1,
  1217	/* 3x */   1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  0,  0,  0,  0,  0,
  1218	/* 4x */   0,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
  1219	/* 5x */   1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  0,  0,  0,  0,  1,
  1220	/* 6x */   0,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
  1221	/* 7x */   1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  0,  0,  0,  1,  0,
  1222	/* 8x */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
  1223	/* 9x */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
  1224	/* Ax */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
  1225	/* Bx */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
  1226	/* Cx */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
  1227	/* Dx */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
  1228	/* Ex */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
  1229	/* Fx */   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
  1230	};
  1231	
  1232	/*
  1233	** Remove all disallowed characters in the input string z[].  Convert any
  1234	** disallowed characters into "_".
  1235	**
  1236	** Not that the three character sequence "%XX" where X is any byte is
  1237	** converted into a single "_" character.
  1238	**
  1239	** Return the number of characters converted.  An "%XX" -> "_" conversion
  1240	** counts as a single character.
  1241	*/
  1242	static int sanitizeString(char *z){
  1243	  int nChange = 0;
  1244	  while( *z ){
  1245	    if( !allowedInName[*(unsigned char*)z] ){
  1246	      if( *z=='%' && z[1]!=0 && z[2]!=0 ){
  1247	        int i;
  1248	        for(i=3; (z[i-2] = z[i])!=0; i++){}
  1249	      }
  1250	      *z = '_';
  1251	      nChange++;
  1252	    }
  1253	    z++;
  1254	  }
  1255	  return nChange;
  1256	}
  1257	
  1258	/*
  1259	** Count the number of "/" characters in a string.
  1260	*/
  1261	static int countSlashes(const char *z){
  1262	  int n = 0;
  1263	  while( *z ) if( *(z++)=='/' ) n++;
  1264	  return n;
  1265	}
  1266	
  1267	/*
  1268	** Transfer nXfer bytes from in to out, after first discarding
  1269	** nSkip bytes from in.  Increment the nOut global variable
  1270	** according to the number of bytes transferred.
  1271	*/
  1272	static void xferBytes(FILE *in, FILE *out, int nXfer, int nSkip){
  1273	  size_t n;
  1274	  size_t got;
  1275	  char zBuf[16384];
  1276	  while( nSkip>0 ){
  1277	    n = nSkip;
  1278	    if( n>sizeof(zBuf) ) n = sizeof(zBuf);
  1279	    got = fread(zBuf, 1, n, in);
  1280	    if( got==0 ) break;
  1281	    nSkip -= got;
  1282	  }
  1283	  while( nXfer>0 ){
  1284	    n = nXfer;
  1285	    if( n>sizeof(zBuf) ) n = sizeof(zBuf);
  1286	    got = fread(zBuf, 1, n, in);
  1287	    if( got==0 ) break;
  1288	    fwrite(zBuf, got, 1, out);
  1289	    nOut += got;
  1290	    nXfer -= got;
  1291	  }
  1292	}
  1293	
  1294	/*
  1295	** Send the text of the file named by zFile as the reply.  Use the
  1296	** suffix on the end of the zFile name to determine the mimetype.
  1297	**
  1298	** Return 1 to omit making a log entry for the reply.
  1299	*/
  1300	static int SendFile(
  1301	  const char *zFile,      /* Name of the file to send */
  1302	  int lenFile,            /* Length of the zFile name in bytes */
  1303	  struct stat *pStat      /* Result of a stat() against zFile */
  1304	){
  1305	  const char *zContentType;
  1306	  time_t t;
  1307	  FILE *in;
  1308	  char zETag[100];
  1309	
  1310	  zContentType = GetMimeType(zFile, lenFile);
  1311	  if( zTmpNam ) unlink(zTmpNam);
  1312	  sprintf(zETag, "m%xs%x", (int)pStat->st_mtime, (int)pStat->st_size);
  1313	  if( CompareEtags(zIfNoneMatch,zETag)==0
  1314	   || (zIfModifiedSince!=0
  1315	        && (t = ParseRfc822Date(zIfModifiedSince))>0
  1316	        && t>=pStat->st_mtime)
  1317	  ){
  1318	    StartResponse("304 Not Modified");
  1319	    nOut += DateTag("Last-Modified", pStat->st_mtime);
  1320	    nOut += printf("Cache-Control: max-age=%d\r\n", mxAge);
  1321	    nOut += printf("ETag: \"%s\"\r\n", zETag);
  1322	    nOut += printf("\r\n");
  1323	    fflush(stdout);
  1324	    MakeLogEntry(0, 470);  /* LOG: ETag Cache Hit */
  1325	    return 1;
  1326	  }
  1327	  in = fopen(zFile,"rb");
  1328	  if( in==0 ) NotFound(480); /* LOG: fopen() failed for static content */
  1329	  if( rangeEnd>0 && rangeStart<pStat->st_size ){
  1330	    StartResponse("206 Partial Content");
  1331	    if( rangeEnd>=pStat->st_size ){
  1332	      rangeEnd = pStat->st_size-1;
  1333	    }
  1334	    nOut += printf("Content-Range: bytes %d-%d/%d\r\n",
  1335	                    rangeStart, rangeEnd, (int)pStat->st_size);
  1336	    pStat->st_size = rangeEnd + 1 - rangeStart;
  1337	  }else{
  1338	    StartResponse("200 OK");
  1339	    rangeStart = 0;
  1340	  }
  1341	  nOut += DateTag("Last-Modified", pStat->st_mtime);
  1342	  nOut += printf("Cache-Control: max-age=%d\r\n", mxAge);
  1343	  nOut += printf("ETag: \"%s\"\r\n", zETag);
  1344	  nOut += printf("Content-type: %s; charset=utf-8\r\n",zContentType);
  1345	  nOut += printf("Content-length: %d\r\n\r\n",(int)pStat->st_size);
  1346	  fflush(stdout);
  1347	  if( strcmp(zMethod,"HEAD")==0 ){
  1348	    MakeLogEntry(0, 2); /* LOG: Normal HEAD reply */
  1349	    fclose(in);
  1350	    fflush(stdout);
  1351	    return 1;
  1352	  }
  1353	  if( useTimeout ) alarm(30 + pStat->st_size/1000);
  1354	#ifdef linux
  1355	  {
  1356	    off_t offset = rangeStart;
  1357	    nOut += sendfile(fileno(stdout), fileno(in), &offset, pStat->st_size);
  1358	  }
  1359	#else
  1360	  xferBytes(in, stdout, (int)pStat->st_size, rangeStart);
  1361	#endif
  1362	  fclose(in);
  1363	  return 0;
  1364	}
  1365	
  1366	/*
  1367	** A CGI or SCGI script has run and is sending its reply back across
  1368	** the channel "in".  Process this reply into an appropriate HTTP reply.
  1369	** Close the "in" channel when done.
  1370	*/
  1371	static void CgiHandleReply(FILE *in){
  1372	  int seenContentLength = 0;   /* True if Content-length: header seen */
  1373	  int contentLength = 0;       /* The content length */
  1374	  size_t nRes = 0;             /* Bytes of payload */
  1375	  size_t nMalloc = 0;          /* Bytes of space allocated to aRes */
  1376	  char *aRes = 0;              /* Payload */
  1377	  int c;                       /* Next character from in */
  1378	  char *z;                     /* Pointer to something inside of zLine */
  1379	  int iStatus = 0;             /* Reply status code */
  1380	  char zLine[1000];            /* One line of reply from the CGI script */
  1381	
  1382	  if( useTimeout ){
  1383	    /* Disable the timeout, so that we can implement Hanging-GET or
  1384	    ** long-poll style CGIs.  The RLIMIT_CPU will serve as a safety
  1385	    ** to help prevent a run-away CGI */
  1386	    alarm(0);
  1387	  }
  1388	  while( fgets(zLine,sizeof(zLine),in) && !isspace((unsigned char)zLine[0]) ){
  1389	    if( strncasecmp(zLine,"Location:",9)==0 ){
  1390	      StartResponse("302 Redirect");
  1391	      RemoveNewline(zLine);
  1392	      z = &zLine[10];
  1393	      while( isspace(*(unsigned char*)z) ){ z++; }
  1394	      nOut += printf("Location: %s\r\n",z);
  1395	      rangeEnd = 0;
  1396	    }else if( strncasecmp(zLine,"Status:",7)==0 ){
  1397	      int i;
  1398	      for(i=7; isspace((unsigned char)zLine[i]); i++){}
  1399	      nOut += printf("%s %s", zProtocol, &zLine[i]);
  1400	      strncpy(zReplyStatus, &zLine[i], 3);
  1401	      zReplyStatus[3] = 0;
  1402	      iStatus = atoi(zReplyStatus);
  1403	      if( iStatus!=200 ) rangeEnd = 0;
  1404	      statusSent = 1;
  1405	    }else if( strncasecmp(zLine, "Content-length:", 15)==0 ){
  1406	      seenContentLength = 1;
  1407	      contentLength = atoi(zLine+15);
  1408	    }else{
  1409	      size_t nLine = strlen(zLine);
  1410	      if( nRes+nLine >= nMalloc ){
  1411	        nMalloc += nMalloc + nLine*2;
  1412	        aRes = realloc(aRes, nMalloc+1);
  1413	        if( aRes==0 ){
  1414	          Malfunction(600, "Out of memory: %d bytes", nMalloc);
  1415	        }
  1416	      }
  1417	      memcpy(aRes+nRes, zLine, nLine);
  1418	      nRes += nLine;
  1419	    }
  1420	  }
  1421	
  1422	  /* Copy everything else thru without change or analysis.
  1423	  */
  1424	  if( rangeEnd>0 && seenContentLength && rangeStart<contentLength ){
  1425	    StartResponse("206 Partial Content");
  1426	    if( rangeEnd>=contentLength ){
  1427	      rangeEnd = contentLength-1;
  1428	    }
  1429	    nOut += printf("Content-Range: bytes %d-%d/%d\r\n",
  1430	                    rangeStart, rangeEnd, contentLength);
  1431	    contentLength = rangeEnd + 1 - rangeStart;
  1432	  }else{
  1433	    StartResponse("200 OK");
  1434	  }
  1435	  if( nRes>0 ){
  1436	    aRes[nRes] = 0;
  1437	    printf("%s", aRes);
  1438	    nOut += nRes;
  1439	    nRes = 0;
  1440	  }
  1441	  if( iStatus==304 ){
  1442	    nOut += printf("\r\n\r\n");
  1443	  }else if( seenContentLength ){
  1444	    nOut += printf("Content-length: %d\r\n\r\n", contentLength);
  1445	    xferBytes(in, stdout, contentLength, rangeStart);
  1446	  }else{
  1447	    while( (c = getc(in))!=EOF ){
  1448	      if( nRes>=nMalloc ){
  1449	        nMalloc = nMalloc*2 + 1000;
  1450	        aRes = realloc(aRes, nMalloc+1);
  1451	        if( aRes==0 ){
  1452	           Malfunction(610, "Out of memory: %d bytes", nMalloc);
  1453	        }
  1454	      }
  1455	      aRes[nRes++] = c;
  1456	    }
  1457	    if( nRes ){
  1458	      aRes[nRes] = 0;
  1459	      nOut += printf("Content-length: %d\r\n\r\n%s", (int)nRes, aRes);
  1460	    }else{
  1461	      nOut += printf("Content-length: 0\r\n\r\n");
  1462	    }
  1463	  }
  1464	  free(aRes);
  1465	  fclose(in);
  1466	}
  1467	
  1468	/*
  1469	** Send an SCGI request to a host identified by zFile and process the
  1470	** reply.
  1471	*/
  1472	static void SendScgiRequest(const char *zFile, const char *zScript){
  1473	  FILE *in;
  1474	  FILE *s;
  1475	  char *z;
  1476	  char *zHost;
  1477	  char *zPort = 0;
  1478	  char *zRelight = 0;
  1479	  char *zFallback = 0;
  1480	  int rc;
  1481	  int iSocket = -1;
  1482	  struct addrinfo hints;
  1483	  struct addrinfo *ai = 0;
  1484	  struct addrinfo *p;
  1485	  char *zHdr;
  1486	  size_t nHdr = 0;
  1487	  size_t nHdrAlloc;
  1488	  int i;
  1489	  char zLine[1000];
  1490	  char zExtra[1000];
  1491	  in = fopen(zFile, "rb");
  1492	  if( in==0 ){
  1493	    Malfunction(700, "cannot open \"%s\"\n", zFile);
  1494	  }
  1495	  if( fgets(zLine, sizeof(zLine)-1, in)==0 ){
  1496	    Malfunction(701, "cannot read \"%s\"\n", zFile);
  1497	  }
  1498	  if( strncmp(zLine,"SCGI ",5)!=0 ){
  1499	    Malfunction(702, "misformatted SCGI spec \"%s\"\n", zFile);
  1500	  }
  1501	  z = zLine+5;
  1502	  zHost = GetFirstElement(z,&z);
  1503	  zPort = GetFirstElement(z,0);
  1504	  if( zHost==0 || zHost[0]==0 || zPort==0 || zPort[0]==0 ){
  1505	    Malfunction(703, "misformatted SCGI spec \"%s\"\n", zFile);
  1506	  }
  1507	  while( fgets(zExtra, sizeof(zExtra)-1, in) ){
  1508	    char *zCmd = GetFirstElement(zExtra,&z);
  1509	    if( zCmd==0 ) continue;
  1510	    if( zCmd[0]=='#' ) continue;
  1511	    RemoveNewline(z);
  1512	    if( strcmp(zCmd, "relight:")==0 ){
  1513	      free(zRelight);
  1514	      zRelight = StrDup(z);
  1515	      continue;
  1516	    }
  1517	    if( strcmp(zCmd, "fallback:")==0 ){
  1518	      free(zFallback);
  1519	      zFallback = StrDup(z);
  1520	      continue;
  1521	    }
  1522	    Malfunction(704, "unrecognized line in SCGI spec: \"%s %s\"\n",
  1523	                zCmd, z ? z : "");
  1524	  }
  1525	  fclose(in);
  1526	  memset(&hints, 0, sizeof(struct addrinfo));
  1527	  hints.ai_family = AF_UNSPEC;
  1528	  hints.ai_socktype = SOCK_STREAM;
  1529	  hints.ai_protocol = IPPROTO_TCP;
  1530	  rc = getaddrinfo(zHost,zPort,&hints,&ai);
  1531	  if( rc ){
  1532	    Malfunction(704, "cannot resolve SCGI server name %s:%s\n%s\n",
  1533	                zHost, zPort, gai_strerror(rc));
  1534	  }
  1535	  while(1){  /* Exit via break */
  1536	    for(p=ai; p; p=p->ai_next){
  1537	      iSocket = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
  1538	      if( iSocket<0 ) continue;
  1539	      if( connect(iSocket,p->ai_addr,p->ai_addrlen)>=0 ) break;
  1540	      close(iSocket);
  1541	    }
  1542	    if( iSocket<0 || (s = fdopen(iSocket,"r+"))==0 ){
  1543	      if( iSocket>=0 ) close(iSocket);
  1544	      if( zRelight ){
  1545	        rc = system(zRelight);
  1546	        if( rc ){
  1547	          Malfunction(721,"Relight failed with %d: \"%s\"\n",
  1548	                      rc, zRelight);
  1549	        }
  1550	        free(zRelight);
  1551	        zRelight = 0;
  1552	        sleep(1);
  1553	        continue;
  1554	      }
  1555	      if( zFallback ){
  1556	        struct stat statbuf;
  1557	        int rc;
  1558	        memset(&statbuf, 0, sizeof(statbuf));
  1559	        if( chdir(zDir) ){
  1560	          char zBuf[1000];
  1561	          Malfunction(720, /* LOG: chdir() failed */
  1562	               "cannot chdir to [%s] from [%s]", 
  1563	               zDir, getcwd(zBuf,999));
  1564	        }
  1565	        rc = stat(zFallback, &statbuf);
  1566	        if( rc==0 && S_ISREG(statbuf.st_mode) && access(zFallback,R_OK)==0 ){
  1567	          closeConnection = 1;
  1568	          rc = SendFile(zFallback, (int)strlen(zFallback), &statbuf);
  1569	          free(zFallback);
  1570	          exit(0);
  1571	        }else{
  1572	          Malfunction(706, "bad fallback file: \"%s\"\n", zFallback);
  1573	        }
  1574	      }
  1575	      Malfunction(707, "cannot open socket to SCGI server %s\n",
  1576	                  zScript);
  1577	    }
  1578	    break;
  1579	  }
  1580	
  1581	  nHdrAlloc = 0;
  1582	  zHdr = 0;
  1583	  if( zContentLength==0 ) zContentLength = "0";
  1584	  zScgi = "1";
  1585	  for(i=0; i<(int)(sizeof(cgienv)/sizeof(cgienv[0])); i++){
  1586	    int n1, n2;
  1587	    if( cgienv[i].pzEnvValue[0]==0 ) continue;
  1588	    n1 = (int)strlen(cgienv[i].zEnvName);
  1589	    n2 = (int)strlen(*cgienv[i].pzEnvValue);
  1590	    if( n1+n2+2+nHdr >= nHdrAlloc ){
  1591	      nHdrAlloc = nHdr + n1 + n2 + 1000;
  1592	      zHdr = realloc(zHdr, nHdrAlloc);
  1593	      if( zHdr==0 ){
  1594	        Malfunction(706, "out of memory");
  1595	      }
  1596	    }
  1597	    memcpy(zHdr+nHdr, cgienv[i].zEnvName, n1);
  1598	    nHdr += n1;
  1599	    zHdr[nHdr++] = 0;
  1600	    memcpy(zHdr+nHdr, *cgienv[i].pzEnvValue, n2);
  1601	    nHdr += n2;
  1602	    zHdr[nHdr++] = 0;
  1603	  }
  1604	  zScgi = 0;
  1605	  fprintf(s,"%d:",(int)nHdr);
  1606	  fwrite(zHdr, 1, nHdr, s);
  1607	  fprintf(s,",");
  1608	  free(zHdr);
  1609	  if( zMethod[0]=='P'
  1610	   && atoi(zContentLength)>0 
  1611	   && (in = fopen(zTmpNam,"r"))!=0 ){
  1612	    size_t n;
  1613	    while( (n = fread(zLine,1,sizeof(zLine),in))>0 ){
  1614	      fwrite(zLine, 1, n, s);
  1615	    }
  1616	    fclose(in);
  1617	  }
  1618	  fflush(s);
  1619	  CgiHandleReply(s);
  1620	}
  1621	
  1622	/*
  1623	** This routine processes a single HTTP request on standard input and
  1624	** sends the reply to standard output.  If the argument is 1 it means
  1625	** that we are should close the socket without processing additional
  1626	** HTTP requests after the current request finishes.  0 means we are
  1627	** allowed to keep the connection open and to process additional requests.
  1628	** This routine may choose to close the connection even if the argument
  1629	** is 0.
  1630	** 
  1631	** If the connection should be closed, this routine calls exit() and
  1632	** thus never returns.  If this routine does return it means that another
  1633	** HTTP request may appear on the wire.
  1634	*/
  1635	void ProcessOneRequest(int forceClose){
  1636	  int i, j, j0;
  1637	  char *z;                  /* Used to parse up a string */
  1638	  struct stat statbuf;      /* Information about the file to be retrieved */
  1639	  FILE *in;                 /* For reading from CGI scripts */
  1640	#ifdef LOG_HEADER
  1641	  FILE *hdrLog = 0;         /* Log file for complete header content */
  1642	#endif
  1643	  char zLine[1000];         /* A buffer for input lines or forming names */
  1644	
  1645	  /* Change directories to the root of the HTTP filesystem
  1646	  */
  1647	  if( chdir(zRoot[0] ? zRoot : "/")!=0 ){
  1648	    char zBuf[1000];
  1649	    Malfunction(190,   /* LOG: chdir() failed */
  1650	         "cannot chdir to [%s] from [%s]",
  1651	         zRoot, getcwd(zBuf,999));
  1652	  }
  1653	  nRequest++;
  1654	
  1655	  /*
  1656	  ** We must receive a complete header within 15 seconds
  1657	  */
  1658	  signal(SIGALRM, Timeout);
  1659	  signal(SIGSEGV, Timeout);
  1660	  signal(SIGPIPE, Timeout);
  1661	  signal(SIGXCPU, Timeout);
  1662	  if( useTimeout ) alarm(15);
  1663	
  1664	  /* Get the first line of the request and parse out the
  1665	  ** method, the script and the protocol.
  1666	  */
  1667	  if( fgets(zLine,sizeof(zLine),stdin)==0 ){
  1668	    exit(0);
  1669	  }
  1670	  gettimeofday(&beginTime, 0);
  1671	  omitLog = 0;
  1672	  nIn += strlen(zLine);
  1673	
  1674	  /* Parse the first line of the HTTP request */
  1675	  zMethod = StrDup(GetFirstElement(zLine,&z));
  1676	  zRealScript = zScript = StrDup(GetFirstElement(z,&z));
  1677	  zProtocol = StrDup(GetFirstElement(z,&z));
  1678	  if( zProtocol==0 || strncmp(zProtocol,"HTTP/",5)!=0 || strlen(zProtocol)!=8 ){
  1679	    StartResponse("400 Bad Request");
  1680	    nOut += printf(
  1681	      "Content-type: text/plain; charset=utf-8\r\n"
  1682	      "\r\n"
  1683	      "This server does not understand the requested protocol\n"
  1684	    );
  1685	    MakeLogEntry(0, 200); /* LOG: bad protocol in HTTP header */
  1686	    exit(0);
  1687	  }
  1688	  if( zScript[0]!='/' ) NotFound(210); /* LOG: Empty request URI */
  1689	  while( zScript[1]=='/' ){
  1690	    zScript++;
  1691	    zRealScript++;
  1692	  }
  1693	  if( forceClose ){
  1694	    closeConnection = 1;
  1695	  }else if( zProtocol[5]<'1' || zProtocol[7]<'1' ){
  1696	    closeConnection = 1;
  1697	  }
  1698	
  1699	  /* This very simple server only understands the GET, POST
  1700	  ** and HEAD methods
  1701	  */
  1702	  if( strcmp(zMethod,"GET")!=0 && strcmp(zMethod,"POST")!=0
  1703	       && strcmp(zMethod,"HEAD")!=0 ){
  1704	    StartResponse("501 Not Implemented");
  1705	    nOut += printf(
  1706	      "Content-type: text/plain; charset=utf-8\r\n"
  1707	      "\r\n"
  1708	      "The %s method is not implemented on this server.\n",
  1709	      zMethod);
  1710	    MakeLogEntry(0, 220); /* LOG: Unknown request method */
  1711	    exit(0);
  1712	  }
  1713	
  1714	  /* If there is a log file (if zLogFile!=0) and if the pathname in
  1715	  ** the first line of the http request contains the magic string
  1716	  ** "FullHeaderLog" then write the complete header text into the
  1717	  ** file %s(zLogFile)-hdr.  Overwrite the file.  This is for protocol
  1718	  ** debugging only and is only enabled if althttpd is compiled with
  1719	  ** the -DLOG_HEADER=1 option.
  1720	  */
  1721	#ifdef LOG_HEADER
  1722	  if( zLogFile
  1723	   && strstr(zScript,"FullHeaderLog")!=0
  1724	   && strlen(zLogFile)<sizeof(zLine)-50
  1725	  ){
  1726	    sprintf(zLine, "%s-hdr", zLogFile);
  1727	    hdrLog = fopen(zLine, "wb");
  1728	  }
  1729	#endif
  1730	
  1731	
  1732	  /* Get all the optional fields that follow the first line.
  1733	  */
  1734	  zCookie = 0;
  1735	  zAuthType = 0;
  1736	  zRemoteUser = 0;
  1737	  zReferer = 0;
  1738	  zIfNoneMatch = 0;
  1739	  zIfModifiedSince = 0;
  1740	  rangeEnd = 0;
  1741	  while( fgets(zLine,sizeof(zLine),stdin) ){
  1742	    char *zFieldName;
  1743	    char *zVal;
  1744	
  1745	#ifdef LOG_HEADER
  1746	    if( hdrLog ) fprintf(hdrLog, "%s", zLine);
  1747	#endif
  1748	    nIn += strlen(zLine);
  1749	    zFieldName = GetFirstElement(zLine,&zVal);
  1750	    if( zFieldName==0 || *zFieldName==0 ) break;
  1751	    RemoveNewline(zVal);
  1752	    if( strcasecmp(zFieldName,"User-Agent:")==0 ){
  1753	      zAgent = StrDup(zVal);
  1754	    }else if( strcasecmp(zFieldName,"Accept:")==0 ){
  1755	      zAccept = StrDup(zVal);
  1756	    }else if( strcasecmp(zFieldName,"Accept-Encoding:")==0 ){
  1757	      zAcceptEncoding = StrDup(zVal);
  1758	    }else if( strcasecmp(zFieldName,"Content-length:")==0 ){
  1759	      zContentLength = StrDup(zVal);
  1760	    }else if( strcasecmp(zFieldName,"Content-type:")==0 ){
  1761	      zContentType = StrDup(zVal);
  1762	    }else if( strcasecmp(zFieldName,"Referer:")==0 ){
  1763	      zReferer = StrDup(zVal);
  1764	      if( strstr(zVal, "devids.net/")!=0 ){ zReferer = "devids.net.smut";
  1765	        Forbidden(230); /* LOG: Referrer is devids.net */
  1766	      }
  1767	    }else if( strcasecmp(zFieldName,"Cookie:")==0 ){
  1768	      zCookie = StrAppend(zCookie,"; ",zVal);
  1769	    }else if( strcasecmp(zFieldName,"Connection:")==0 ){
  1770	      if( strcasecmp(zVal,"close")==0 ){
  1771	        closeConnection = 1;
  1772	      }else if( !forceClose && strcasecmp(zVal, "keep-alive")==0 ){
  1773	        closeConnection = 0;
  1774	      }
  1775	    }else if( strcasecmp(zFieldName,"Host:")==0 ){
  1776	      int inSquare = 0;
  1777	      char c;
  1778	      if( sanitizeString(zVal) ){
  1779	        Forbidden(240);  /* LOG: Illegal content in HOST: parameter */
  1780	      }
  1781	      zHttpHost = StrDup(zVal);
  1782	      zServerPort = zServerName = StrDup(zHttpHost);
  1783	      while( zServerPort && (c = *zServerPort)!=0
  1784	              && (c!=':' || inSquare) ){
  1785	        if( c=='[' ) inSquare = 1;
  1786	        if( c==']' ) inSquare = 0;
  1787	        zServerPort++;
  1788	      }
  1789	      if( zServerPort && *zServerPort ){
  1790	        *zServerPort = 0;
  1791	        zServerPort++;
  1792	      }
  1793	      if( zRealPort ){
  1794	        zServerPort = StrDup(zRealPort);
  1795	      }
  1796	    }else if( strcasecmp(zFieldName,"Authorization:")==0 ){
  1797	      zAuthType = GetFirstElement(StrDup(zVal), &zAuthArg);
  1798	    }else if( strcasecmp(zFieldName,"If-None-Match:")==0 ){
  1799	      zIfNoneMatch = StrDup(zVal);
  1800	    }else if( strcasecmp(zFieldName,"If-Modified-Since:")==0 ){
  1801	      zIfModifiedSince = StrDup(zVal);
  1802	    }else if( strcasecmp(zFieldName,"Range:")==0
  1803	           && strcmp(zMethod,"GET")==0 ){
  1804	      int x1 = 0, x2 = 0;
  1805	      int n = sscanf(zVal, "bytes=%d-%d", &x1, &x2);
  1806	      if( n==2 && x1>=0 && x2>=x1 ){
  1807	        rangeStart = x1;
  1808	        rangeEnd = x2;
  1809	      }else if( n==1 && x1>0 ){
  1810	        rangeStart = x1;
  1811	        rangeEnd = 0x7fffffff;
  1812	      }
  1813	    }
  1814	  }
  1815	#ifdef LOG_HEADER
  1816	  if( hdrLog ) fclose(hdrLog);
  1817	#endif
  1818	
  1819	  /* Disallow requests from certain clients */
  1820	  if( zAgent ){
  1821	    const char *azDisallow[] = {
  1822	      "Windows 9",
  1823	      "Download Master",
  1824	      "Ezooms/",
  1825	      "HTTrace",
  1826	      "AhrefsBot",
  1827	      "MicroMessenger",
  1828	      "OPPO A33 Build",
  1829	      "SemrushBot",
  1830	      "MegaIndex.ru",
  1831	      "MJ12bot",
  1832	      "Chrome/0.A.B.C",
  1833	      "Neevabot/",
  1834	      "BLEXBot/",
  1835	    };
  1836	    size_t ii;
  1837	    for(ii=0; ii<sizeof(azDisallow)/sizeof(azDisallow[0]); ii++){
  1838	      if( strstr(zAgent,azDisallow[ii])!=0 ){
  1839	        Forbidden(250);  /* LOG: Disallowed user agent */
  1840	      }
  1841	    }
  1842	#if 0
  1843	    /* Spider attack from 2019-04-24 */
  1844	    if( strcmp(zAgent,
  1845	            "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 "
  1846	            "(KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36")==0 ){
  1847	      Forbidden(251);  /* LOG: Disallowed user agent (20190424) */
  1848	    }
  1849	#endif
  1850	  }
  1851	#if 0
  1852	  if( zReferer ){
  1853	    static const char *azDisallow[] = {
  1854	      "skidrowcrack.com",
  1855	      "hoshiyuugi.tistory.com",
  1856	      "skidrowgames.net",
  1857	    };
  1858	    int i;
  1859	    for(i=0; i<sizeof(azDisallow)/sizeof(azDisallow[0]); i++){
  1860	      if( strstr(zReferer, azDisallow[i])!=0 ){
  1861	        NotFound(260);  /* LOG: Disallowed referrer */
  1862	      }
  1863	    }
  1864	  }
  1865	#endif
  1866	
  1867	  /* Make an extra effort to get a valid server name and port number.
  1868	  ** Only Netscape provides this information.  If the browser is
  1869	  ** Internet Explorer, then we have to find out the information for
  1870	  ** ourselves.
  1871	  */
  1872	  if( zServerName==0 ){
  1873	    zServerName = SafeMalloc( 100 );
  1874	    gethostname(zServerName,100);
  1875	  }
  1876	  if( zServerPort==0 || *zServerPort==0 ){
  1877	    zServerPort = DEFAULT_PORT;
  1878	  }
  1879	
  1880	  /* Remove the query string from the end of the requested file.
  1881	  */
  1882	  for(z=zScript; *z && *z!='?'; z++){}
  1883	  if( *z=='?' ){
  1884	    zQuerySuffix = StrDup(z);
  1885	    *z = 0;
  1886	  }else{
  1887	    zQuerySuffix = "";
  1888	  }
  1889	  zQueryString = *zQuerySuffix ? &zQuerySuffix[1] : zQuerySuffix;
  1890	
  1891	  /* Create a file to hold the POST query data, if any.  We have to
  1892	  ** do it this way.  We can't just pass the file descriptor down to
  1893	  ** the child process because the fgets() function may have already
  1894	  ** read part of the POST data into its internal buffer.
  1895	  */
  1896	  if( zMethod[0]=='P' && zContentLength!=0 ){
  1897	    size_t len = atoi(zContentLength);
  1898	    FILE *out;
  1899	    char *zBuf;
  1900	    int n;
  1901	
  1902	    if( len>MAX_CONTENT_LENGTH ){
  1903	      StartResponse("500 Request too large");
  1904	      nOut += printf(
  1905	        "Content-type: text/plain; charset=utf-8\r\n"
  1906	        "\r\n"
  1907	        "Too much POST data\n"
  1908	      );
  1909	      MakeLogEntry(0, 270); /* LOG: Request too large */
  1910	      exit(0);
  1911	    }
  1912	    rangeEnd = 0;
  1913	    sprintf(zTmpNamBuf, "/tmp/-post-data-XXXXXX");
  1914	    zTmpNam = zTmpNamBuf;
  1915	    if( mkstemp(zTmpNam)<0 ){
  1916	      Malfunction(280,  /* LOG: mkstemp() failed */
  1917	               "Cannot create a temp file in which to store POST data");
  1918	    }
  1919	    out = fopen(zTmpNam,"wb");
  1920	    if( out==0 ){
  1921	      StartResponse("500 Cannot create /tmp file");
  1922	      nOut += printf(
  1923	        "Content-type: text/plain; charset=utf-8\r\n"
  1924	        "\r\n"
  1925	        "Could not open \"%s\" for writing\n", zTmpNam
  1926	      );
  1927	      MakeLogEntry(0, 290); /* LOG: cannot create temp file for POST */
  1928	      exit(0);
  1929	    }
  1930	    zBuf = SafeMalloc( len+1 );
  1931	    if( useTimeout ) alarm(15 + len/2000);
  1932	    n = fread(zBuf,1,len,stdin);
  1933	    nIn += n;
  1934	    fwrite(zBuf,1,n,out);
  1935	    free(zBuf);
  1936	    fclose(out);
  1937	  }
  1938	
  1939	  /* Make sure the running time is not too great */
  1940	  if( useTimeout ) alarm(10);
  1941	
  1942	  /* Convert all unusual characters in the script name into "_".
  1943	  **
  1944	  ** This is a defense against various attacks, XSS attacks in particular.
  1945	  */
  1946	  sanitizeString(zScript);
  1947	
  1948	  /* Do not allow "/." or "/-" to to occur anywhere in the entity name.
  1949	  ** This prevents attacks involving ".." and also allows us to create
  1950	  ** files and directories whose names begin with "-" or "." which are
  1951	  ** invisible to the webserver.
  1952	  **
  1953	  ** Exception:  Allow the "/.well-known/" prefix in accordance with
  1954	  ** RFC-5785.
  1955	  */
  1956	  for(z=zScript; *z; z++){
  1957	    if( *z=='/' && (z[1]=='.' || z[1]=='-') ){
  1958	      if( strncmp(zScript,"/.well-known/",13)==0 && (z[1]!='.' || z[2]!='.') ){
  1959	        /* Exception:  Allow "/." and "/-" for URLs that being with
  1960	        ** "/.well-known/".  But do not allow "/..". */
  1961	        continue;
  1962	      }
  1963	      NotFound(300); /* LOG: Path element begins with "." or "-" */
  1964	    }
  1965	  }
  1966	
  1967	  /* Figure out what the root of the filesystem should be.  If the
  1968	  ** HTTP_HOST parameter exists (stored in zHttpHost) then remove the
  1969	  ** port number from the end (if any), convert all characters to lower
  1970	  ** case, and convert non-alphanumber characters (including ".") to "_".
  1971	  ** Then try to find a directory with that name and the extension .website.
  1972	  ** If not found, look for "default.website".
  1973	  */
  1974	  if( zScript[0]!='/' ){
  1975	    NotFound(310); /* LOG: URI does not start with "/" */
  1976	  }
  1977	  if( strlen(zRoot)+40 >= sizeof(zLine) ){
  1978	    NotFound(320); /* LOG: URI too long */
  1979	  }
  1980	  if( zHttpHost==0 || zHttpHost[0]==0 ){
  1981	    NotFound(330);  /* LOG: Missing HOST: parameter */
  1982	  }else if( strlen(zHttpHost)+strlen(zRoot)+10 >= sizeof(zLine) ){
  1983	    NotFound(340);  /* LOG: HOST parameter too long */
  1984	  }else{
  1985	    sprintf(zLine, "%s/%s", zRoot, zHttpHost);
  1986	    for(i=strlen(zRoot)+1; zLine[i] && zLine[i]!=':'; i++){
  1987	      unsigned char c = (unsigned char)zLine[i];
  1988	      if( !isalnum(c) ){
  1989	        if( c=='.' && (zLine[i+1]==0 || zLine[i+1]==':') ){
  1990	          /* If the client sent a FQDN with a "." at the end
  1991	          ** (example: "sqlite.org." instead of just "sqlite.org") then
  1992	          ** omit the final "." from the document root directory name */
  1993	          break;
  1994	        }
  1995	        zLine[i] = '_';
  1996	      }else if( isupper(c) ){
  1997	        zLine[i] = tolower(c);
  1998	      }
  1999	    }
  2000	    strcpy(&zLine[i], ".website");
  2001	  }
  2002	  if( stat(zLine,&statbuf) || !S_ISDIR(statbuf.st_mode) ){
  2003	    sprintf(zLine, "%s/default.website", zRoot);
  2004	    if( stat(zLine,&statbuf) || !S_ISDIR(statbuf.st_mode) ){
  2005	      if( standalone ){
  2006	        sprintf(zLine, "%s", zRoot);
  2007	      }else{
  2008	        NotFound(350);  /* LOG: *.website permissions */
  2009	      }
  2010	    }
  2011	  }
  2012	  zHome = StrDup(zLine);
  2013	
  2014	  /* Change directories to the root of the HTTP filesystem
  2015	  */
  2016	  if( chdir(zHome)!=0 ){
  2017	    char zBuf[1000];
  2018	    Malfunction(360,  /* LOG: chdir() failed */
  2019	         "cannot chdir to [%s] from [%s]",
  2020	         zHome, getcwd(zBuf,999));
  2021	  }
  2022	
  2023	  /* Locate the file in the filesystem.  We might have to append
  2024	  ** a name like "/home" or "/index.html" or "/index.cgi" in order
  2025	  ** to find it.  Any excess path information is put into the
  2026	  ** zPathInfo variable.
  2027	  */
  2028	  j = j0 = (int)strlen(zLine);
  2029	  i = 0;
  2030	  while( zScript[i] ){
  2031	    while( zScript[i] && (i==0 || zScript[i]!='/') ){
  2032	      zLine[j] = zScript[i];
  2033	      i++; j++;
  2034	    }
  2035	    zLine[j] = 0;
  2036	    if( stat(zLine,&statbuf)!=0 ){
  2037	      int stillSearching = 1;
  2038	      while( stillSearching && i>0 && j>j0 ){
  2039	        while( j>j0 && zLine[j-1]!='/' ){ j--; }
  2040	        strcpy(&zLine[j-1], "/not-found.html");
  2041	        if( stat(zLine,&statbuf)==0 && S_ISREG(statbuf.st_mode)
  2042	            && access(zLine,R_OK)==0 ){
  2043	          zRealScript = StrDup(&zLine[j0]);
  2044	          Redirect(zRealScript, 302, 1, 370); /* LOG: redirect to not-found */
  2045	          return;
  2046	        }else{
  2047	          j--;
  2048	        }
  2049	      }
  2050	      if( stillSearching ) NotFound(380); /* LOG: URI not found */
  2051	      break;
  2052	    }
  2053	    if( S_ISREG(statbuf.st_mode) ){
  2054	      if( access(zLine,R_OK) ){
  2055	        NotFound(390);  /* LOG: File not readable */
  2056	      }
  2057	      zRealScript = StrDup(&zLine[j0]);
  2058	      break;
  2059	    }
  2060	    if( zScript[i]==0 || zScript[i+1]==0 ){
  2061	      static const char *azIndex[] = { "/home", "/index.html", "/index.cgi" };
  2062	      int k = j>0 && zLine[j-1]=='/' ? j-1 : j;
  2063	      unsigned int jj;
  2064	      for(jj=0; jj<sizeof(azIndex)/sizeof(azIndex[0]); jj++){
  2065	        strcpy(&zLine[k],azIndex[jj]);
  2066	        if( stat(zLine,&statbuf)!=0 ) continue;
  2067	        if( !S_ISREG(statbuf.st_mode) ) continue;
  2068	        if( access(zLine,R_OK) ) continue;
  2069	        break;
  2070	      }
  2071	      if( jj>=sizeof(azIndex)/sizeof(azIndex[0]) ){
  2072	        NotFound(400); /* LOG: URI is a directory w/o index.html */
  2073	      }
  2074	      zRealScript = StrDup(&zLine[j0]);
  2075	      if( zScript[i]==0 ){
  2076	        /* If the requested URL does not end with "/" but we had to
  2077	        ** append "index.html", then a redirect is necessary.  Otherwise
  2078	        ** none of the relative URLs in the delivered document will be
  2079	        ** correct. */
  2080	        Redirect(zRealScript,301,1,410); /* LOG: redirect to add trailing / */
  2081	        return;
  2082	      }
  2083	      break;
  2084	    }
  2085	    zLine[j] = zScript[i];
  2086	    i++; j++;
  2087	  }
  2088	  zFile = StrDup(zLine);
  2089	  zPathInfo = StrDup(&zScript[i]);
  2090	  lenFile = strlen(zFile);
  2091	  zDir = StrDup(zFile);
  2092	  for(i=strlen(zDir)-1; i>0 && zDir[i]!='/'; i--){};
  2093	  if( i==0 ){
  2094	     strcpy(zDir,"/");
  2095	  }else{
  2096	     zDir[i] = 0;
  2097	  }
  2098	
  2099	  /* Check to see if there is an authorization file.  If there is,
  2100	  ** process it.
  2101	  */
  2102	  sprintf(zLine, "%s/-auth", zDir);
  2103	  if( access(zLine,R_OK)==0 && !CheckBasicAuthorization(zLine) ) return;
  2104	
  2105	  /* Take appropriate action
  2106	  */
  2107	  if( (statbuf.st_mode & 0100)==0100 && access(zFile,X_OK)==0 ){
  2108	    char *zBaseFilename;         /* Filename without directory prefix */
  2109	
  2110	    /*
  2111	    ** Abort with an error if the CGI script is writable by anyone other
  2112	    ** than its owner.
  2113	    */
  2114	    if( statbuf.st_mode & 0022 ){
  2115	      CgiScriptWritable();
  2116	    }
  2117	
  2118	    /* If its executable, it must be a CGI program.  Start by
  2119	    ** changing directories to the directory holding the program.
  2120	    */
  2121	    if( chdir(zDir) ){
  2122	      char zBuf[1000];
  2123	      Malfunction(420, /* LOG: chdir() failed */
  2124	           "cannot chdir to [%s] from [%s]", 
  2125	           zDir, getcwd(zBuf,999));
  2126	    }
  2127	
  2128	    /* Compute the base filename of the CGI script */
  2129	    for(i=strlen(zFile)-1; i>=0 && zFile[i]!='/'; i--){}
  2130	    zBaseFilename = &zFile[i+1];
  2131	
  2132	    /* Setup the environment appropriately.
  2133	    */
  2134	    putenv("GATEWAY_INTERFACE=CGI/1.0");
  2135	    for(i=0; i<(int)(sizeof(cgienv)/sizeof(cgienv[0])); i++){
  2136	      if( *cgienv[i].pzEnvValue ){
  2137	        SetEnv(cgienv[i].zEnvName,*cgienv[i].pzEnvValue);
  2138	      }
  2139	    }
  2140	    if( useHttps ){
  2141	      putenv("HTTPS=on");
  2142	      putenv("REQUEST_SCHEME=https");
  2143	    }else{
  2144	      putenv("REQUEST_SCHEME=http");
  2145	    }
  2146	
  2147	    /* For the POST method all input has been written to a temporary file,
  2148	    ** so we have to redirect input to the CGI script from that file.
  2149	    */
  2150	    if( zMethod[0]=='P' ){
  2151	      if( dup(0)<0 ){
  2152	        Malfunction(430,  /* LOG: dup(0) failed */
  2153	                    "Unable to duplication file descriptor 0");
  2154	      }
  2155	      close(0);
  2156	      open(zTmpNam, O_RDONLY);
  2157	    }
  2158	
  2159	    if( strncmp(zBaseFilename,"nph-",4)==0 ){
  2160	      /* If the name of the CGI script begins with "nph-" then we are
  2161	      ** dealing with a "non-parsed headers" CGI script.  Just exec()
  2162	      ** it directly and let it handle all its own header generation.
  2163	      */
  2164	      execl(zBaseFilename,zBaseFilename,(char*)0);
  2165	      /* NOTE: No log entry written for nph- scripts */
  2166	      exit(0);
  2167	    }
  2168	
  2169	    /* Fall thru to here only if this process (the server) is going
  2170	    ** to read and augment the header sent back by the CGI process.
  2171	    ** Open a pipe to receive the output from the CGI process.  Then
  2172	    ** fork the CGI process.  Once everything is done, we should be
  2173	    ** able to read the output of CGI on the "in" stream.
  2174	    */
  2175	    {
  2176	      int px[2];
  2177	      if( pipe(px) ){
  2178	        Malfunction(440, /* LOG: pipe() failed */
  2179	                    "Unable to create a pipe for the CGI program");
  2180	      }
  2181	      if( fork()==0 ){
  2182	        close(px[0]);
  2183	        close(1);
  2184	        if( dup(px[1])!=1 ){
  2185	          Malfunction(450, /* LOG: dup(1) failed */
  2186	                 "Unable to duplicate file descriptor %d to 1",
  2187	                 px[1]);
  2188	        }
  2189	        close(px[1]);
  2190	        for(i=3; close(i)==0; i++){}
  2191	        execl(zBaseFilename, zBaseFilename, (char*)0);
  2192	        exit(0);
  2193	      }
  2194	      close(px[1]);
  2195	      in = fdopen(px[0], "rb");
  2196	    }
  2197	    if( in==0 ){
  2198	      CgiError();
  2199	    }else{
  2200	      CgiHandleReply(in);
  2201	    }
  2202	  }else if( lenFile>5 && strcmp(&zFile[lenFile-5],".scgi")==0 ){
  2203	    /* Any file that ends with ".scgi" is assumed to be text of the
  2204	    ** form:
  2205	    **     SCGI hostname port
  2206	    ** Open a TCP/IP connection to that host and send it an SCGI request
  2207	    */
  2208	    SendScgiRequest(zFile, zScript);
  2209	  }else if( countSlashes(zRealScript)!=countSlashes(zScript) ){
  2210	    /* If the request URI for static content contains material past the
  2211	    ** actual content file name, report that as a 404 error. */
  2212	    NotFound(460); /* LOG: Excess URI content past static file name */
  2213	  }else{
  2214	    /* If it isn't executable then it
  2215	    ** must a simple file that needs to be copied to output.
  2216	    */
  2217	    if( SendFile(zFile, lenFile, &statbuf) ) return;
  2218	  }
  2219	  fflush(stdout);
  2220	  MakeLogEntry(0, 0);  /* LOG: Normal reply */
  2221	
  2222	  /* The next request must arrive within 30 seconds or we close the connection
  2223	  */
  2224	  omitLog = 1;
  2225	  if( useTimeout ) alarm(30);
  2226	}
  2227	
  2228	#define MAX_PARALLEL 50  /* Number of simultaneous children */
  2229	
  2230	/*
  2231	** All possible forms of an IP address.  Needed to work around GCC strict
  2232	** aliasing rules.
  2233	*/
  2234	typedef union {
  2235	  struct sockaddr sa;              /* Abstract superclass */
  2236	  struct sockaddr_in sa4;          /* IPv4 */
  2237	  struct sockaddr_in6 sa6;         /* IPv6 */
  2238	  struct sockaddr_storage sas;     /* Should be the maximum of the above 3 */
  2239	} address;
  2240	
  2241	/*
  2242	** Implement an HTTP server daemon listening on port zPort.
  2243	**
  2244	** As new connections arrive, fork a child and let the child return
  2245	** out of this procedure call.  The child will handle the request.
  2246	** The parent never returns from this procedure.
  2247	**
  2248	** Return 0 to each child as it runs.  If unable to establish a
  2249	** listening socket, return non-zero.
  2250	*/
  2251	int http_server(const char *zPort, int localOnly){
  2252	  int listener[20];            /* The server sockets */
  2253	  int connection;              /* A socket for each individual connection */
  2254	  fd_set readfds;              /* Set of file descriptors for select() */
  2255	  address inaddr;              /* Remote address */
  2256	  socklen_t lenaddr;           /* Length of the inaddr structure */
  2257	  int child;                   /* PID of the child process */
  2258	  int nchildren = 0;           /* Number of child processes */
  2259	  struct timeval delay;        /* How long to wait inside select() */
  2260	  int opt = 1;                 /* setsockopt flag */
  2261	  struct addrinfo sHints;      /* Address hints */
  2262	  struct addrinfo *pAddrs, *p; /* */
  2263	  int rc;                      /* Result code */
  2264	  int i, n;
  2265	  int maxFd = -1;
  2266	  
  2267	  memset(&sHints, 0, sizeof(sHints));
  2268	  if( ipv4Only ){
  2269	    sHints.ai_family = PF_INET;
  2270	    /*printf("ipv4 only\n");*/
  2271	  }else if( ipv6Only ){
  2272	    sHints.ai_family = PF_INET6;
  2273	    /*printf("ipv6 only\n");*/
  2274	  }else{
  2275	    sHints.ai_family = PF_UNSPEC;
  2276	  }
  2277	  sHints.ai_socktype = SOCK_STREAM;
  2278	  sHints.ai_flags = AI_PASSIVE;
  2279	  sHints.ai_protocol = 0;
  2280	  rc = getaddrinfo(localOnly ? "localhost": 0, zPort, &sHints, &pAddrs);
  2281	  if( rc ){
  2282	    fprintf(stderr, "could not get addr info: %s", 
  2283	            rc!=EAI_SYSTEM ? gai_strerror(rc) : strerror(errno));
  2284	    return 1;
  2285	  }
  2286	  for(n=0, p=pAddrs; n<(int)(sizeof(listener)/sizeof(listener[0])) && p!=0;
  2287	        p=p->ai_next){
  2288	    listener[n] = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
  2289	    if( listener[n]>=0 ){
  2290	      /* if we can't terminate nicely, at least allow the socket to be reused */
  2291	      setsockopt(listener[n], SOL_SOCKET, SO_REUSEADDR,&opt, sizeof(opt));
  2292	      
  2293	#if defined(IPV6_V6ONLY)
  2294	      if( p->ai_family==AF_INET6 ){
  2295	        int v6only = 1;
  2296	        setsockopt(listener[n], IPPROTO_IPV6, IPV6_V6ONLY,
  2297	                    &v6only, sizeof(v6only));
  2298	      }
  2299	#endif
  2300	      
  2301	      if( bind(listener[n], p->ai_addr, p->ai_addrlen)<0 ){
  2302	        printf("bind failed: %s\n", strerror(errno));
  2303	        close(listener[n]);
  2304	        continue;
  2305	      }
  2306	      if( listen(listener[n], 20)<0 ){
  2307	        printf("listen() failed: %s\n", strerror(errno));
  2308	        close(listener[n]);
  2309	        continue;
  2310	      }
  2311	      n++;
  2312	    }
  2313	  }
  2314	  if( n==0 ){
  2315	    fprintf(stderr, "cannot open any sockets\n");
  2316	    return 1;
  2317	  }
  2318	
  2319	  while( 1 ){
  2320	    if( nchildren>MAX_PARALLEL ){
  2321	      /* Slow down if connections are arriving too fast */
  2322	      sleep( nchildren-MAX_PARALLEL );
  2323	    }
  2324	    delay.tv_sec = 60;
  2325	    delay.tv_usec = 0;
  2326	    FD_ZERO(&readfds);
  2327	    for(i=0; i<n; i++){
  2328	      assert( listener[i]>=0 );
  2329	      FD_SET( listener[i], &readfds);
  2330	      if( listener[i]>maxFd ) maxFd = listener[i];
  2331	    }
  2332	    select( maxFd+1, &readfds, 0, 0, &delay);
  2333	    for(i=0; i<n; i++){
  2334	      if( FD_ISSET(listener[i], &readfds) ){
  2335	        lenaddr = sizeof(inaddr);
  2336	        connection = accept(listener[i], &inaddr.sa, &lenaddr);
  2337	        if( connection>=0 ){
  2338	          child = fork();
  2339	          if( child!=0 ){
  2340	            if( child>0 ) nchildren++;
  2341	            close(connection);
  2342	            /* printf("subprocess %d started...\n", child); fflush(stdout); */
  2343	          }else{
  2344	            int nErr = 0, fd;
  2345	            close(0);
  2346	            fd = dup(connection);
  2347	            if( fd!=0 ) nErr++;
  2348	            close(1);
  2349	            fd = dup(connection);
  2350	            if( fd!=1 ) nErr++;
  2351	            close(connection);
  2352	            return nErr;
  2353	          }
  2354	        }
  2355	      }
  2356	      /* Bury dead children */
  2357	      while( (child = waitpid(0, 0, WNOHANG))>0 ){
  2358	        /* printf("process %d ends\n", child); fflush(stdout); */
  2359	        nchildren--;
  2360	      }
  2361	    }
  2362	  }
  2363	  /* NOT REACHED */  
  2364	  exit(1);
  2365	}
  2366	
  2367	
  2368	int main(int argc, char **argv){
  2369	  int i;                    /* Loop counter */
  2370	  char *zPermUser = 0;      /* Run daemon with this user's permissions */
  2371	  const char *zPort = 0;    /* Implement an HTTP server process */
  2372	  int useChrootJail = 1;    /* True to use a change-root jail */
  2373	  struct passwd *pwd = 0;   /* Information about the user */
  2374	
  2375	  /* Record the time when processing begins.
  2376	  */
  2377	  gettimeofday(&beginTime, 0);
  2378	
  2379	  /* Parse command-line arguments
  2380	  */
  2381	  while( argc>1 && argv[1][0]=='-' ){
  2382	    char *z = argv[1];
  2383	    char *zArg = argc>=3 ? argv[2] : "0";
  2384	    if( z[0]=='-' && z[1]=='-' ) z++;
  2385	    if( strcmp(z,"-user")==0 ){
  2386	      zPermUser = zArg;
  2387	    }else if( strcmp(z,"-root")==0 ){
  2388	      zRoot = zArg;
  2389	    }else if( strcmp(z,"-logfile")==0 ){
  2390	      zLogFile = zArg;
  2391	    }else if( strcmp(z,"-max-age")==0 ){
  2392	      mxAge = atoi(zArg);
  2393	    }else if( strcmp(z,"-max-cpu")==0 ){
  2394	      maxCpu = atoi(zArg);
  2395	    }else if( strcmp(z,"-https")==0 ){
  2396	      useHttps = atoi(zArg);
  2397	      zHttp = useHttps ? "https" : "http";
  2398	      if( useHttps ) zRemoteAddr = getenv("REMOTE_HOST");
  2399	    }else if( strcmp(z, "-port")==0 ){
  2400	      zPort = zArg;
  2401	      standalone = 1;
  2402	     
  2403	    }else if( strcmp(z, "-family")==0 ){
  2404	      if( strcmp(zArg, "ipv4")==0 ){
  2405	        ipv4Only = 1;
  2406	      }else if( strcmp(zArg, "ipv6")==0 ){
  2407	        ipv6Only = 1;
  2408	      }else{
  2409	        Malfunction(500,  /* LOG: unknown IP protocol */
  2410	                    "unknown IP protocol: [%s]\n", zArg);
  2411	      }
  2412	    }else if( strcmp(z, "-jail")==0 ){
  2413	      if( atoi(zArg)==0 ){
  2414	        useChrootJail = 0;
  2415	      }
  2416	    }else if( strcmp(z, "-debug")==0 ){
  2417	      if( atoi(zArg) ){
  2418	        useTimeout = 0;
  2419	      }
  2420	    }else if( strcmp(z, "-input")==0 ){
  2421	      if( freopen(zArg, "rb", stdin)==0 || stdin==0 ){
  2422	        Malfunction(501, /* LOG: cannot open --input file */
  2423	                    "cannot open --input file \"%s\"\n", zArg);
  2424	      }
  2425	    }else if( strcmp(z, "-datetest")==0 ){
  2426	      TestParseRfc822Date();
  2427	      printf("Ok\n");
  2428	      exit(0);
  2429	    }else{
  2430	      Malfunction(510, /* LOG: unknown command-line argument on launch */
  2431	                  "unknown argument: [%s]\n", z);
  2432	    }
  2433	    argv += 2;
  2434	    argc -= 2;
  2435	  }
  2436	  if( zRoot==0 ){
  2437	    if( standalone ){
  2438	      zRoot = ".";
  2439	    }else{
  2440	      Malfunction(520, /* LOG: --root argument missing */
  2441	                  "no --root specified");
  2442	    }
  2443	  }
  2444	  
  2445	  /* Change directories to the root of the HTTP filesystem.  Then
  2446	  ** create a chroot jail there.
  2447	  */
  2448	  if( chdir(zRoot)!=0 ){
  2449	    Malfunction(530, /* LOG: chdir() failed */
  2450	                "cannot change to directory [%s]", zRoot);
  2451	  }
  2452	
  2453	  /* Get information about the user if available */
  2454	  if( zPermUser ) pwd = getpwnam(zPermUser);
  2455	
  2456	  /* Enter the chroot jail if requested */  
  2457	  if( zPermUser && useChrootJail && getuid()==0 ){
  2458	    if( chroot(".")<0 ){
  2459	      Malfunction(540, /* LOG: chroot() failed */
  2460	                  "unable to create chroot jail");
  2461	    }else{
  2462	      zRoot = "";
  2463	    }
  2464	  }
  2465	
  2466	  /* Activate the server, if requested */
  2467	  if( zPort && http_server(zPort, 0) ){
  2468	    Malfunction(550, /* LOG: server startup failed */
  2469	                "failed to start server");
  2470	  }
  2471	
  2472	#ifdef RLIMIT_CPU
  2473	  if( maxCpu>0 ){
  2474	    struct rlimit rlim;
  2475	    rlim.rlim_cur = maxCpu;
  2476	    rlim.rlim_max = maxCpu;
  2477	    setrlimit(RLIMIT_CPU, &rlim);
  2478	  }
  2479	#endif
  2480	
  2481	  /* Drop root privileges.
  2482	  */
  2483	  if( zPermUser ){
  2484	    if( pwd ){
  2485	      if( setgid(pwd->pw_gid) ){
  2486	        Malfunction(560, /* LOG: setgid() failed */
  2487	                    "cannot set group-id to %d", pwd->pw_gid);
  2488	      }
  2489	      if( setuid(pwd->pw_uid) ){
  2490	        Malfunction(570, /* LOG: setuid() failed */
  2491	                    "cannot set user-id to %d", pwd->pw_uid);
  2492	      }
  2493	    }else{
  2494	      Malfunction(580, /* LOG: unknown user */
  2495	                  "no such user [%s]", zPermUser);
  2496	    }
  2497	  }
  2498	  if( getuid()==0 ){
  2499	    Malfunction(590, /* LOG: cannot run as root */
  2500	                "cannot run as root");
  2501	  }
  2502	
  2503	  /* Get the IP address from whence the request originates
  2504	  */
  2505	  if( zRemoteAddr==0 ){
  2506	    address remoteAddr;
  2507	    unsigned int size = sizeof(remoteAddr);
  2508	    char zHost[NI_MAXHOST];
  2509	    if( getpeername(0, &remoteAddr.sa, &size)>=0 ){
  2510	      getnameinfo(&remoteAddr.sa, size, zHost, sizeof(zHost), 0, 0,
  2511	                  NI_NUMERICHOST);
  2512	      zRemoteAddr = StrDup(zHost);
  2513	    }
  2514	  }
  2515	  if( zRemoteAddr!=0
  2516	   && strncmp(zRemoteAddr, "::ffff:", 7)==0
  2517	   && strchr(zRemoteAddr+7, ':')==0
  2518	   && strchr(zRemoteAddr+7, '.')!=0
  2519	  ){
  2520	    zRemoteAddr += 7;
  2521	  }
  2522	
  2523	  /* Process the input stream */
  2524	  for(i=0; i<100; i++){
  2525	    ProcessOneRequest(0);
  2526	  }
  2527	  ProcessOneRequest(1);
  2528	  exit(0);
  2529	}
  2530	
  2531	#if 0
  2532	/* Copy/paste the following text into SQLite to generate the xref
  2533	** table that describes all error codes.
  2534	*/
  2535	BEGIN;
  2536	CREATE TABLE IF NOT EXISTS xref(lineno INTEGER PRIMARY KEY, desc TEXT);
  2537	DELETE FROM Xref;
  2538	INSERT INTO xref VALUES(100,'Malloc() failed');
  2539	INSERT INTO xref VALUES(110,'Not authorized');
  2540	INSERT INTO xref VALUES(120,'CGI Error');
  2541	INSERT INTO xref VALUES(130,'Timeout');
  2542	INSERT INTO xref VALUES(140,'CGI script is writable');
  2543	INSERT INTO xref VALUES(150,'Cannot open -auth file');
  2544	INSERT INTO xref VALUES(160,'http request on https-only page');
  2545	INSERT INTO xref VALUES(170,'-auth redirect');
  2546	INSERT INTO xref VALUES(180,'malformed entry in -auth file');
  2547	INSERT INTO xref VALUES(190,'chdir() failed');
  2548	INSERT INTO xref VALUES(200,'bad protocol in HTTP header');
  2549	INSERT INTO xref VALUES(210,'Empty request URI');
  2550	INSERT INTO xref VALUES(220,'Unknown request method');
  2551	INSERT INTO xref VALUES(230,'Referrer is devids.net');
  2552	INSERT INTO xref VALUES(240,'Illegal content in HOST: parameter');
  2553	INSERT INTO xref VALUES(250,'Disallowed user agent');
  2554	INSERT INTO xref VALUES(260,'Disallowed referrer');
  2555	INSERT INTO xref VALUES(270,'Request too large');
  2556	INSERT INTO xref VALUES(280,'mkstemp() failed');
  2557	INSERT INTO xref VALUES(290,'cannot create temp file for POST content');
  2558	INSERT INTO xref VALUES(300,'Path element begins with . or -');
  2559	INSERT INTO xref VALUES(310,'URI does not start with /');
  2560	INSERT INTO xref VALUES(320,'URI too long');
  2561	INSERT INTO xref VALUES(330,'Missing HOST: parameter');
  2562	INSERT INTO xref VALUES(340,'HOST parameter too long');
  2563	INSERT INTO xref VALUES(350,'*.website permissions');
  2564	INSERT INTO xref VALUES(360,'chdir() failed');
  2565	INSERT INTO xref VALUES(370,'redirect to not-found page');
  2566	INSERT INTO xref VALUES(380,'URI not found');
  2567	INSERT INTO xref VALUES(390,'File not readable');
  2568	INSERT INTO xref VALUES(400,'URI is a directory w/o index.html');
  2569	INSERT INTO xref VALUES(410,'redirect to add trailing /');
  2570	INSERT INTO xref VALUES(420,'chdir() failed');
  2571	INSERT INTO xref VALUES(430,'dup(0) failed');
  2572	INSERT INTO xref VALUES(440,'pipe() failed');
  2573	INSERT INTO xref VALUES(450,'dup(1) failed');
  2574	INSERT INTO xref VALUES(460,'Excess URI content past static file name');
  2575	INSERT INTO xref VALUES(470,'ETag Cache Hit');
  2576	INSERT INTO xref VALUES(480,'fopen() failed for static content');
  2577	INSERT INTO xref VALUES(2,'Normal HEAD reply');
  2578	INSERT INTO xref VALUES(0,'Normal reply');
  2579	INSERT INTO xref VALUES(500,'unknown IP protocol');
  2580	INSERT INTO xref VALUES(501,'cannot open --input file');
  2581	INSERT INTO xref VALUES(510,'unknown command-line argument on launch');
  2582	INSERT INTO xref VALUES(520,'--root argument missing');
  2583	INSERT INTO xref VALUES(530,'chdir() failed');
  2584	INSERT INTO xref VALUES(540,'chroot() failed');
  2585	INSERT INTO xref VALUES(550,'server startup failed');
  2586	INSERT INTO xref VALUES(560,'setgid() failed');
  2587	INSERT INTO xref VALUES(570,'setuid() failed');
  2588	INSERT INTO xref VALUES(580,'unknown user');
  2589	INSERT INTO xref VALUES(590,'cannot run as root');
  2590	INSERT INTO xref VALUES(600,'malloc() failed');
  2591	INSERT INTO xref VALUES(610,'malloc() failed');
  2592	COMMIT;
  2593	#endif /* SQL */
