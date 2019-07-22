/*
 * Copyright (C) 2016 Jorge Pereira <jpereiran@gmail.com>
 */

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <memory.h>

#include <libunwind.h> /* from -llibuwind */

#if defined(REG_RIP)
# define SIGSEGV_STACK_IA64
# define REGFORMAT "%016lx"
#elif defined(REG_EIP)
# define SIGSEGV_STACK_X86
# define REGFORMAT "%08x"
#else
# define SIGSEGV_STACK_GENERIC
# define REGFORMAT "%x"
#endif

#define NGX_BACKTRACE_DEFAULT_STACK_MAX_SIZE 30

static char *ngx_backtrace_files(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void ngx_error_signal_handler(int signo, siginfo_t *info, void *secret);
static ngx_int_t ngx_backtrace_init_module(ngx_cycle_t *cycle);
static void *ngx_backtrace_create_conf(ngx_cycle_t *cycle);
#if defined(nginx_version) && nginx_version >= 1005002
static ngx_log_t *ngx_log_create(ngx_cycle_t *cycle, ngx_str_t *name);
#endif

typedef struct {
    int     signo;
    char   *signame;
    char   *name;
    void  (*handler)(int sig, siginfo_t *info, void *secret);
} ngx_signal_t;

typedef struct {
    ngx_log_t  *log;
    ngx_int_t  max_stack_size;
} ngx_backtrace_conf_t;

static ngx_signal_t  ngx_backtrace_signals[] = {
    { SIGABRT, "SIGABRT", "", ngx_error_signal_handler },
#ifdef SIGBUS
    { SIGBUS, "SIGBUS", "", ngx_error_signal_handler },
#endif
    { SIGFPE, "SIGFPE", "", ngx_error_signal_handler },
    { SIGILL, "SIGILL", "", ngx_error_signal_handler },
    { SIGIOT, "SIGIOT", "", ngx_error_signal_handler },
    { SIGSEGV, "SIGSEGV", "", ngx_error_signal_handler },
    { 0, NULL, "", NULL }
};

typedef struct {
    int signo;
    int si_code;
    const char *si_code_desc;
} sig_action_map_t;

static sig_action_map_t ngx_backtrace_si_codes[] = {
    { SIGSEGV, SEGV_MAPERR, "SEGV_MAPERR (Address not mapped to object)" },
    { SIGSEGV, SEGV_ACCERR, "SEGV_ACCERR (Invalid permissions for mapped object)" },
    { SIGSEGV, -1,          "Unknown reason" }
};

const char *ngx_si_code2desc(int signo, int si_code) {
    sig_action_map_t *p;

    for (p = &ngx_backtrace_si_codes[0]; p->signo != -1; p++) {
        if (p->signo == signo) {
            return (p->si_code == si_code) ? p->si_code_desc : "Unknown reason";
        }
    }

    return NULL;
}

static ngx_command_t ngx_backtrace_commands[] = {

    { ngx_string("backtrace_log"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_backtrace_files,
      0,
      0,
      NULL },

    { ngx_string("backtrace_max_stack_size"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_backtrace_conf_t, max_stack_size),
      NULL },

      ngx_null_command
};

static ngx_core_module_t  ngx_backtrace_module_ctx = {
    ngx_string("backtrace"),
    ngx_backtrace_create_conf,
    NULL
};

ngx_module_t  ngx_backtrace_module = {
    NGX_MODULE_V1,
    &ngx_backtrace_module_ctx,             /* module context */
    ngx_backtrace_commands,                /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_backtrace_init_module,             /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

#if defined(nginx_version) && nginx_version >= 1005002
static ngx_log_t *
ngx_log_create (ngx_cycle_t *cycle, ngx_str_t *name)
{
    ngx_log_t  *log;

    log = ngx_pcalloc(cycle->pool, sizeof(ngx_log_t));
    if (log == NULL) {
        return NULL;
    }

    log->file = ngx_conf_open_file(cycle, name);
    if (log->file == NULL) {
        return NULL;
    }

    return log;
}
#endif

const char *ngx_backtrace_get_proc_exe (pid_t pid) {
    char proc_pid[64];
    static char proc_buf[64];
    
    snprintf(proc_pid, sizeof(proc_buf), "/proc/%d/exe", pid);

    if (readlink(proc_pid, proc_buf, sizeof(proc_buf)-1) < 1) {
        perror("readlink");
        return NULL;
    }

    return (const char *)&proc_buf[0];
}

static ngx_int_t
ngx_init_error_signals (ngx_log_t *log)
{
    ngx_signal_t      *sig;
    struct sigaction   sa;

    for (sig = ngx_backtrace_signals; sig->signo != 0; sig++) {
        ngx_memzero(&sa, sizeof(struct sigaction));
        sa.sa_sigaction = sig->handler;
        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);

        if (sigaction(sig->signo, &sa, NULL) == -1) {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                          "ngx_backtrace_module: sigaction(%s) failed", sig->signame);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static void
ngx_error_signal_handler (int signo, siginfo_t *info, void *ptr) {
    ngx_log_t            *log;
    ngx_signal_t         *sig;
    struct sigaction      sa;
    ngx_backtrace_conf_t *bcf;
    int                   nptrs;
    int                   ret;
    int                   fd;
    time_t                crash_time;
    const char           *si_code_reason;
    const char           *proc_exe;
    unw_cursor_t          cursor; 
    unw_context_t         uc;

    bcf = (ngx_backtrace_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                                ngx_backtrace_module);

    log = bcf->log ? bcf->log : ngx_cycle->log;

    for (sig = ngx_backtrace_signals; sig->signo != 0; sig++) {
        if (sig->signo == signo) {
            break;
        }
    }
    
    if (sig == 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "ngx_backtrace_module: Wrong signal received from Kernel! Weird!!");
        return;
    }

    ngx_log_error(NGX_LOG_ERR, log, 0,
                    "ngx_backtrace_module: Got signal %d (%s), Saving the stacktrace in %s", 
                    signo, sig->signame, (char *)log->file->name.data
    );

    fd = log->file->fd;
    if (fcntl(fd, F_GETFL) < 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                    "ngx_backtrace_module: We can't write into the file %s, exiting.",
                    (char *)log->file->name.data
        );
        goto bye;
    }

    dprintf(fd, "+-------------------------------------------------------+\n");
    dprintf(fd, "| ngx_backtrace_module: Received signal %d (%s)\n", signo, sig->signame);
    dprintf(fd, "+-------------------------------------------------------+\n");

    crash_time = time(NULL);
    dprintf(fd, " Date: %s", ctime(&crash_time));
    dprintf(fd, " Faulty address: %p\n", info->si_addr);
    dprintf(fd, " PID: %ld\n", (long)getpid());
    dprintf(fd, " PPID: %ld\n", (long)getppid());

    proc_exe = ngx_backtrace_get_proc_exe(getpid());
    dprintf(fd, " Binary name: %s\n", proc_exe);
    dprintf(fd, " Signal Code: %d\n", info->si_code);

    si_code_reason = ngx_si_code2desc(signo, info->si_code);
    dprintf(fd, " Signal Reason: %s\n", si_code_reason);
    dprintf(fd, "+-------------------------------------------------------+\n");

    ngx_memzero(&sa, sizeof(struct sigaction));
    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);
    if (sigaction(signo, &sa, NULL) == -1) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "ngx_backtrace_module: sigaction(%s) failed", sig->signame);
    }

    if (bcf->max_stack_size == NGX_CONF_UNSET) {
        bcf->max_stack_size = NGX_BACKTRACE_DEFAULT_STACK_MAX_SIZE;
    }

    dprintf(fd, "Stack trace:\n");

    ret = unw_getcontext(&uc);
    if (ret != UNW_ESUCCESS) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "ngx_backtrace_module: Problems with unw_getcontext() ret=%d", ret);
        goto invalid;
    }

    ret = unw_init_local (&cursor, &uc);
    if (ret != 0) {
        dprintf(fd, "Problems with unw_init_local() failed: ret=%d\n", ret);
        goto invalid;
    }

    for (nptrs = 0; unw_step(&cursor) > 0; nptrs++) {
        char fname[128] = { '\0', };
        unw_word_t ip, sp, offp;

        unw_get_proc_name (&cursor, fname, sizeof(fname), &offp);

        ret = unw_get_reg (&cursor, UNW_REG_IP, &ip);
        if (ret != 0) {
            dprintf(fd, "Problems with unw_get_reg(UNW_REG_IP) failed: ret=%d\n", ret);
            goto invalid;
        }

        ret = unw_get_reg (&cursor, UNW_REG_SP, &sp);
        if (ret != 0) {
            dprintf(fd, "Problems with unw_get_reg(UNW_REG_SP) failed: ret=%d\n", ret);
            goto invalid;
        }

        if (!strcmp(fname, "__restore_rt")) continue;
        if (!strcmp(fname, "__libc_start_main")) break;

        dprintf(fd, "\t#%02d: 0x"REGFORMAT" in %s(), sp = 0x"REGFORMAT"\n",
                nptrs, (long) ip, fname[0] ? fname : "??", (long) sp);
    }

    dprintf(fd, "End of stack trace.\n\n");

    fsync(fd);

bye:

    return;
invalid:

    kill(ngx_getpid(), signo);
}

static char *
ngx_backtrace_files(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t             file, *value;
    ngx_log_t            *log;
    ngx_backtrace_conf_t *bcf;

    bcf = (ngx_backtrace_conf_t *) ngx_get_conf(cf->cycle->conf_ctx,
                                                ngx_backtrace_module);

    value = cf->args->elts;
    file = value[1];

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0, 
                "ngx_backtrace_module: Initializing the module saving in %s", file.data);

    if (ngx_conf_full_name(cf->cycle, &file, 1) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    log = ngx_log_create(cf->cycle, &file);
    if (log == NULL) {
        return NGX_CONF_ERROR;
    }

    bcf->log = log;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_backtrace_init_module(ngx_cycle_t *cycle)
{
    ngx_backtrace_conf_t *bcf;

    bcf = (ngx_backtrace_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_backtrace_module);

    if (!bcf->log) {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "ngx_backtrace_module: The module is not in use");
        return NGX_OK;
    }

    if (ngx_init_error_signals(cycle->log) == NGX_ERROR) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void *
ngx_backtrace_create_conf(ngx_cycle_t *cycle)
{
    ngx_backtrace_conf_t  *bcf;

    bcf = ngx_pcalloc(cycle->pool, sizeof(ngx_backtrace_conf_t));
    if (bcf == NULL) {
        return NULL;
    }

    bcf->max_stack_size = NGX_CONF_UNSET;

    return bcf;
}
