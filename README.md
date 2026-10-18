# nginx-backtrace-ng

[![CI](https://github.com/jpereira/nginx-backtrace-ng/actions/workflows/ci.yml/badge.svg)](https://github.com/jpereira/nginx-backtrace-ng/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![nginx](https://img.shields.io/badge/nginx-1.26%20%7C%201.31-009639?logo=nginx&logoColor=white)](https://nginx.org)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04-E95420?logo=ubuntu&logoColor=white)](https://ubuntu.com)
[![Debian](https://img.shields.io/badge/Debian-12-A81D33?logo=debian&logoColor=white)](https://www.debian.org)
[![Language: C](https://img.shields.io/badge/language-C-555555.svg)](ngx_backtrace_module.c)
[![Last commit](https://img.shields.io/github/last-commit/jpereira/nginx-backtrace-ng)](https://github.com/jpereira/nginx-backtrace-ng/commits/master)

nginx module that dumps a stack trace (via libunwind) when an nginx process, master or
worker, receives a fatal signal: `SIGABRT`, `SIGBUS`, `SIGFPE`, `SIGILL`, `SIGIOT` or
`SIGSEGV`. Handy for debugging crashes without core files.

Tested on Ubuntu 24.04 and Debian 12 with nginx 1.31.7 and 1.26.2 (see [Tests](#tests)).

## Quick start

```
sudo apt-get install build-essential libunwind-dev libpcre2-dev zlib1g-dev
cd nginx-1.31.7/
./configure --prefix=/opt/nginx --add-module=/path/to/nginx-backtrace-ng
make && make install
```

Or, with the `Makefile` of this repo:

```
make deps                              # apt build dependencies (needs sudo)
make install NGINX_SRC=/path/to/nginx  # PREFIX=/opt/nginx by default
```

Then, in `nginx.conf` (main context):

```
backtrace_log /var/log/nginx/backtrace.log;
```

The module requires [libunwind](http://www.nongnu.org/libunwind/) and is only active when
`backtrace_log` is set. Without it, nginx logs "The module is not in use".

## Directives

### backtrace_log

**Syntax**: `backtrace_log path;`
**Default**: none (module disabled)
**Context**: main

File where the stack trace is written.

### backtrace_max_stack_size

**Syntax**: `backtrace_max_stack_size size;`
**Default**: `30`
**Context**: main

Maximum stack depth of the backtrace.

## Sample

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

## Tests

The suite builds nginx with the module in a clean Docker image and crashes the processes
with signals (SEGV/ABRT/FPE on the worker, SEGV on the master), then checks the backtrace
file. It also covers config validation and the "module not in use" case. Stack traces are
printed during the run.

```
make help          # list targets
make test          # Ubuntu 24.04 + Debian 12
make test-ubuntu   # only Ubuntu
make test-debian   # only Debian
make shell-debian  # shell inside the test image
make clean         # remove the test images
```

Another nginx release: `make test NGINX_VERSION=1.26.2`. Remote Docker host:
`docker context use <name>`.

To trigger a crash by hand, `tests/cgi-bin/gerar-crash.cgi` sends a signal to a worker
(via `fcgiwrap`, inside the test image):

```
curl 'http://127.0.0.1:8080/cgi-bin/gerar-crash.cgi?sig=SEGV'   # SEGV|ABRT|FPE|BUS|ILL
```

CI (`.github/workflows/ci.yml`) runs the same suite on Ubuntu and Debian for each nginx
version above.

## Notes

* The handler restores `SIG_DFL` after dumping, so a signal sent with `kill` doesn't
  terminate the process the first time; a real fault does.
* The "Got signal ..." message is not written, because the backtrace log is created with
  log level 0.

## License

See [LICENSE](LICENSE).
