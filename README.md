# nginx-backtrace-ng

[![CI](https://github.com/jpereira/nginx-backtrace-ng/actions/workflows/ci.yml/badge.svg)](https://github.com/jpereira/nginx-backtrace-ng/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![nginx](https://img.shields.io/badge/nginx-1.26%20%7C%201.31-009639?logo=nginx&logoColor=white)](https://nginx.org)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04-E95420?logo=ubuntu&logoColor=white)](https://ubuntu.com)
[![Debian](https://img.shields.io/badge/Debian-12-A81D33?logo=debian&logoColor=white)](https://www.debian.org)
[![Language: C](https://img.shields.io/badge/language-C-555555.svg)](ngx_backtrace_module.c)
[![Last commit](https://img.shields.io/github/last-commit/jpereira/nginx-backtrace-ng)](https://github.com/jpereira/nginx-backtrace-ng/commits/master)

nginx module that saves a stack trace when an nginx process (master or worker) gets a fatal
signal: `SIGABRT`, `SIGBUS`, `SIGFPE`, `SIGILL`, `SIGIOT` or `SIGSEGV`.

If you are writing your own nginx modules, you need this. A bug in your handler or filter
just kills the worker and you have no clue why. With this module you get the stack trace
right in a log file, with function names and the faulting address. No core dump, no gdb, no
need to reproduce it under a debugger first.

It uses [libunwind](http://www.nongnu.org/libunwind/) to walk the stack and get the function
names, so you need it to build (`libunwind-dev` on Debian/Ubuntu).

Tested on Ubuntu 24.04 and Debian 12 (x86_64 and aarch64), with nginx 1.31.7 and 1.26.2.
See [Tests](#tests).

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

The module only works if `backtrace_log` is set. Without it, nginx just logs "The module is
not in use".

## Directives

### backtrace_log

**Syntax**: `backtrace_log path;`
**Default**: none (module disabled)
**Context**: main

File where the stack trace goes.

### backtrace_max_stack_size

**Syntax**: `backtrace_max_stack_size size;`
**Default**: `30`
**Context**: main

How many frames to save, at most.

## Sample

Real output, from a NULL write in a handler (`/crash?mode=null`, see [Tests](#tests)):

```
# cat /tmp/nginx-crash.log
2026/10/18 20:02:34 [error] 12#0: ngx_backtrace_module: Got signal 11 (SIGSEGV), Saving the stacktrace in /tmp/nginx-crash.log
+-------------------------------------------------------+
| ngx_backtrace_module: Received signal 11 (SIGSEGV)
+-------------------------------------------------------+
 Date: Sun Oct 18 20:02:34 2026
 Faulty address: (nil)
 PID: 12
 PPID: 10
 Binary name: /opt/nginx/sbin/nginx
 Signal Code: 1
 Signal Reason: SEGV_MAPERR (Address not mapped to object)
+-------------------------------------------------------+
Stack trace:
	#00: 0x00005561eddb7aac in ngx_http_crash_test_handler(), sp = 0x00007ffda6dd0210
	#01: 0x00005561edd26664 in ngx_http_core_content_phase(), sp = 0x00007ffda6dd0230
	#02: 0x00005561edd2590b in ngx_http_core_run_phases(), sp = 0x00007ffda6dd0280
	#03: 0x00005561edd25874 in ngx_http_handler(), sp = 0x00007ffda6dd02c0
	#04: 0x00005561edd34fca in ngx_http_process_request(), sp = 0x00007ffda6dd02f0
	#05: 0x00005561edd339b9 in ngx_http_process_request_headers(), sp = 0x00007ffda6dd0320
	#06: 0x00005561edd32e81 in ngx_http_process_request_line(), sp = 0x00007ffda6dd03a0
	#07: 0x00005561edd325a9 in ngx_http_wait_request_handler(), sp = 0x00007ffda6dd0410
	#08: 0x00005561edd1eaca in ngx_epoll_process_events(), sp = 0x00007ffda6dd0470
	#09: 0x00005561edd0e01f in ngx_process_events_and_timers(), sp = 0x00007ffda6dd04f0
	#10: 0x00005561edd1c334 in ngx_worker_process_cycle(), sp = 0x00007ffda6dd0530
	#11: 0x00005561edd18f41 in ngx_spawn_process(), sp = 0x00007ffda6dd0560
	#12: 0x00005561edd1b4d9 in ngx_start_worker_processes(), sp = 0x00007ffda6dd05c0
	#13: 0x00005561edd1acaa in ngx_master_process_cycle(), sp = 0x00007ffda6dd0600
	#14: 0x00005561edcd1ca2 in main(), sp = 0x00007ffda6dd0710
	#15: 0x00007f3e6b4921ca in __libc_init_first(), sp = 0x00007ffda6dd09f0
End of stack trace.
```

## Tests

The suite builds nginx with the module in a clean Docker image, crashes the processes with
signals (SEGV/ABRT/FPE on the worker, SEGV on the master) and checks the backtrace file. It
also tests the config validation and the "module not in use" case. The stack traces are
printed while it runs.

```
make help          # list targets
make test          # Ubuntu 24.04 + Debian 12
make test-ubuntu   # only Ubuntu
make test-debian   # only Debian
make shell-debian  # shell inside the test image
make clean         # remove the test images
```

Want another nginx version? `make test NGINX_VERSION=1.26.2`. Want to run on a remote Docker
host? `docker context use <name>` first.

To crash it by hand, `tests/cgi-bin/gerar-crash.cgi` sends a signal to a worker (it runs
with `fcgiwrap`, inside the test image):

```
curl 'http://127.0.0.1:8080/cgi-bin/gerar-crash.cgi?sig=SEGV'   # SEGV|ABRT|FPE|BUS|ILL
```

The suite also crashes a worker for real, with `tests/crash-module` (a tiny nginx module just
for tests): a NULL write and an infinite recursion (stack overflow). Try it by hand:

```
curl 'http://127.0.0.1:8080/crash?mode=null'    # or mode=stack
```

The CI (`.github/workflows/ci.yml`) runs the same suite on Ubuntu and Debian, with both nginx
versions, on x86_64 and aarch64.

## Notes

* The handler runs on its own stack, so stack overflows get dumped too.
* After the dump the handler goes back to `SIG_DFL`. So a signal sent with `kill` doesn't
  kill the process the first time (a real fault does).

## License

See [LICENSE](LICENSE).
