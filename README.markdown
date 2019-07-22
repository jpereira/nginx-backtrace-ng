Name
====

* Backtrace module (ng).

Description
===========

* It can be used to dump backtrace of nginx in case an Nginx process (master or worker) exits abnormally, e.g. when some signal is received (SIGABR, SIGBUS, SIGFPE, SIGILL, SIGIOT, SIGSEGV). It's quite handy for debugging purpose.
* This module requires the libunwind API. You can't enable it on systems lack of this library, Check if your system is supported in http://www.nongnu.org/libunwind/index.html

Installing Dependencies (Debian/Ubuntu)
==========

```
sudo apt-get install libunwind-dev
```

Build
==========

```
cd nginx-1.9.7/
./configure --prefix=/opt --add-module=/path/to/nginx-backtrace-ng
make
make install
```
 
Directives
==========

backtrace_log
-------------

**Syntax**: *backtrace_log log_path*
**Default**: *backtrace_log error.log*
**Context**: *main*

Specify the log file name of backtrace.
backtrace_log /path/to/backtrace.log

backtrace_max_stack_size
------------------------

**Syntax**: *backtrace_max_stack_size size*
**Default**: *backtrace_max_stack_size 30*
**Context**: *main*

Specify the maximum stack depth for backtrace

Backtrace Sample
==========

```
# tail -1 logs/error.log 
2016/11/29 02:47:53 [error] 21810#0: ngx_backtrace_module: Got signal 11 (SIGSEGV), Saving the stacktrace in /tmp/nginx-crash.log
# cat /tmp/nginx-crash.log
+-------------------------------------------------------+
| ngx_backtrace_module: Received signal 11 (SIGSEGV)
+-------------------------------------------------------+
 Date: Tue Nov 29 02:47:53 2016
 Faulty address: 0xd3adbeef
 PID: 21810
 PPID: 21809
 Binary name: /opt/nginx/sbin/nginx
 Signal Code: 1
 Signal Reason: SEGV_MAPERR (Address not mapped to object)
+-------------------------------------------------------+
Stack trace:
	#01: 0x00000000d3adbeef in ??(), sp = 0x00007ffe433b3cb8
	#02: 0x0000557e25d696cb in ngx_http_process_request(), sp = 0x00007ffe433b3cc8
	#03: 0x0000557e25d535e5 in ngx_os_specific_status(), sp = 0x00007ffe433b3d40
	#04: 0x0000557e25d4b3b8 in ngx_process_events_and_timers(), sp = 0x00007ffe433b3da0
	#05: 0x0000557e25d513ef in ngx_libc_crypt(), sp = 0x00007ffe433b3de0
	#06: 0x0000557e25d4fd11 in ngx_spawn_process(), sp = 0x00007ffe433b3e00
	#07: 0x0000557e25d515d0 in ngx_libc_crypt(), sp = 0x00007ffe433b3e80
	#08: 0x0000557e25d52132 in ngx_master_process_cycle(), sp = 0x00007ffe433b3f00
	#09: 0x0000557e25d2ff8a in main(), sp = 0x00007ffe433b4070
End of stack trace.

```

