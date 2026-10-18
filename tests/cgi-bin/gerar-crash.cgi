#!/bin/sh
# Usage: curl 'http://127.0.0.1:8080/cgi-bin/gerar-crash.cgi?sig=SEGV'
# Sends the signal to an nginx worker, so ngx_backtrace_module dumps the stack trace.
sig=${QUERY_STRING#sig=}
case "$sig" in
    SEGV|ABRT|FPE|BUS|ILL) ;;
    *) sig=SEGV ;;
esac

pid=$(pgrep -f "nginx: worker" | head -1)

printf 'Content-Type: text/plain\r\n\r\n'
echo "sending SIG$sig to nginx worker $pid"
kill -"$sig" "$pid"
