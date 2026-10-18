#!/bin/bash
# Runs inside the container: starts nginx with the module and crashes it with signals.
NGINX=/opt/nginx/sbin/nginx
CONF=/opt/nginx/conf/nginx.conf
BTLOG=/tmp/backtrace.log
PIDFILE=/opt/nginx/logs/nginx.pid
pass=0; fail=0

ok()   { echo "  [PASS] $1"; pass=$((pass+1)); }
nok()  { echo "  [FAIL] $1"; fail=$((fail+1)); }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else nok "$d"; fi; }

write_conf() { # $1 = extra main-context directives
    cat > $CONF <<CFG
error_log logs/error.log notice;
$1
daemon on;
master_process on;
worker_processes 1;
events { worker_connections 64; }
http { server { listen 8080; location / { return 200 "ok\n"; }
    location /cgi-bin/ {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME /tests\$fastcgi_script_name;
        fastcgi_pass unix:/tmp/fcgi.sock;
    } } }
CFG
}

stop_nginx() {
    pkill -9 nginx 2>/dev/null
    sleep 0.3
    rm -f $BTLOG $PIDFILE /opt/nginx/logs/error.log
}

start_nginx() {
    $NGINX && sleep 0.5
    curl -fs http://127.0.0.1:8080/ >/dev/null
}

is_dead() { [ ! -d /proc/$1 ] || grep -q '^State:.*Z' /proc/$1/status; }
worker_pid() { pgrep -f "nginx: worker" | head -1; }
master_pid() { cat $PIDFILE; }

crash_test() { # $1=signal name  $2=target (worker|master)
    local sig=$1 target=$2 pid
    echo "== $sig on $target"
    stop_nginx
    write_conf "backtrace_log $BTLOG;"
    check "nginx starts and serves" start_nginx
    pid=$([ "$target" = master ] && master_pid || worker_pid)
    kill -$sig "$pid"
    sleep 1
    echo "  --- $BTLOG ---"; sed 's/^/    /' $BTLOG 2>/dev/null; echo "  ---"
    check "backtrace file created"      test -s $BTLOG
    check "reports signal $sig"         grep -q "Received signal .* (SIG$sig)" $BTLOG
    check "has PID of target"           grep -q " PID: $pid" $BTLOG
    check "has binary name"             grep -q "Binary name: /opt/nginx/sbin/nginx" $BTLOG
    check "has stack trace"             grep -q "^Stack trace:" $BTLOG
    check "has 'End of stack trace'"    grep -q "End of stack trace" $BTLOG
    check "has at least one frame"      grep -qE "#[0-9]+: 0x[0-9a-f]+ in " $BTLOG
    check "dump notice written"         grep -q "Got signal .* (SIG$sig)" $BTLOG
    check "signal reason resolved"      grep -q "Signal Reason: " $BTLOG
    # handler restores SIG_DFL, so a 2nd signal must terminate the process
    kill -$sig "$pid" 2>/dev/null; sleep 1
    check "2nd signal kills (SIG_DFL)"  is_dead $pid
}

echo "== config validation"
stop_nginx
write_conf "backtrace_log $BTLOG; backtrace_max_stack_size 10;"
check "nginx -t with both directives" $NGINX -t
write_conf "backtrace_max_stack_size abc;"
check "rejects non-numeric stack size" bash -c "! $NGINX -t"
write_conf "backtrace_log;"
check "rejects backtrace_log without arg" bash -c "! $NGINX -t"

echo "== module disabled without backtrace_log"
stop_nginx
write_conf ""
check "nginx starts" start_nginx
check "logs 'not in use'" grep -q "The module is not in use" /opt/nginx/logs/error.log
kill -SEGV "$(worker_pid)"; sleep 1
check "no backtrace file written" test ! -e $BTLOG

echo "== crash triggered by CGI (HTTP request)"
stop_nginx
rm -f /tmp/fcgi.sock
fcgiwrap -s unix:/tmp/fcgi.sock & sleep 0.5
chmod 777 /tmp/fcgi.sock
write_conf "backtrace_log $BTLOG;"
check "nginx starts and serves" start_nginx
wpid=$(worker_pid)
check "CGI answers" curl -fs "http://127.0.0.1:8080/cgi-bin/gerar-crash.cgi?sig=SEGV"
sleep 1
echo "  --- $BTLOG ---"; sed 's/^/    /' $BTLOG 2>/dev/null; echo "  ---"
check "backtrace written by CGI trigger" grep -q "Received signal .* (SIGSEGV)" $BTLOG
check "PID is the worker's"              grep -q " PID: $wpid" $BTLOG
pkill fcgiwrap

echo "== backtrace_max_stack_size limits the frames"
stop_nginx
write_conf "backtrace_log $BTLOG; backtrace_max_stack_size 2;"
check "nginx starts and serves" start_nginx
kill -SEGV "$(worker_pid)"; sleep 1
check "at most 2 frames" test "$(grep -cE '#[0-9]+: 0x' $BTLOG)" -eq 2

crash_test SEGV worker
crash_test ABRT worker
crash_test FPE  worker
crash_test SEGV master

stop_nginx
echo
echo "Result: $pass passed, $fail failed"
[ $fail -eq 0 ]
