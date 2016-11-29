Description
===========

* It can be used to dump backtrace of nginx in case a worker process exits abnormally, e.g. when some signal is received (SIGABR, SIGBUS, SIGFPE, SIGILL, SIGIOT, SIGSEGV). It's quite handy for debugging purpose.
* It is possible to catch the signals from the nginx master and worker processes.
* This module requires the libunwind API. Check if your architecture is supported in http://www.nongnu.org/libunwind/index.html

Installing Dependencies (Debian/Ubuntu)
==========

```
sudo apt-get install libunwind-dev
```

Build
==========

```
cd nginx-1.9.7/
./configure --prefix=/opt --add-module=/path/to/nginx-backtrace
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
