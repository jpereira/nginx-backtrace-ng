/*
 * Test only: "crash_test;" in a location makes the worker really fault.
 *   /crash?mode=null   NULL pointer write (SIGSEGV, SEGV_MAPERR)
 *   /crash?mode=stack  infinite recursion (SIGSEGV from a stack overflow)
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static char *ngx_http_crash_test(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t ngx_http_crash_test_commands[] = {

    { ngx_string("crash_test"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_crash_test,
      0,
      0,
      NULL },

      ngx_null_command
};

static ngx_http_module_t ngx_http_crash_test_module_ctx = {
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

ngx_module_t ngx_http_crash_test_module = {
    NGX_MODULE_V1,
    &ngx_http_crash_test_module_ctx,
    ngx_http_crash_test_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};

static int ngx_http_crash_test_recurse(int n);
static int (*volatile ngx_http_crash_test_fn)(int) = ngx_http_crash_test_recurse;

static int
ngx_http_crash_test_recurse(int n)
{
    volatile char buf[512];

    buf[0] = (char) n;

    return ngx_http_crash_test_fn(n + 1) + buf[0];
}

ngx_int_t
ngx_http_crash_test_handler(ngx_http_request_t *r)
{
    if (r->args.len >= 10 && ngx_strncmp(r->args.data, "mode=stack", 10) == 0) {
        ngx_http_crash_test_fn(0);
    }

    *(volatile int *) 0 = 1;

    return NGX_OK;
}

static char *
ngx_http_crash_test(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_crash_test_handler;

    return NGX_CONF_OK;
}
