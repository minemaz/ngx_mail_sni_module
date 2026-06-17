/*
 * ngx_mail_sni_module - SNI based dynamic server certificate selection
 *                       for the nginx mail proxy (IMAP/POP3/SMTP),
 *                       including STARTTLS.
 *
 * The stock nginx mail module binds one certificate per listening socket and
 * does NOT support SNI based certificate selection (unlike the http/stream
 * modules). This loadable module adds it without patching nginx core.
 *
 * At worker start (init_process), it walks every mail server's SSL_CTX and
 * registers an OpenSSL certificate callback (SSL_CTX_set_cert_cb). At the TLS
 * handshake the callback reads the SNI host name and loads
 * <ssl_sni_certificates_path>/<servername>.{crt,key} dynamically, falling back
 * to the configured ssl_certificate when there is no match.
 *
 * Because the certificate is chosen during the TLS handshake, this works for
 * STARTTLS too (the SNI is in the ClientHello sent after the STARTTLS command),
 * which L4 SNI routing (stream ssl_preread) cannot do.
 *
 * Technique (dynamic certificate loading at the TLS handshake via
 * SSL_CTX_set_cert_cb) is taken, with gratitude, from:
 *   R. Matsumoto, Y. Miyake, K. Rikitake, K. Kuribayashi,
 *   "Large-scale Certificate Management on Highly-integrated Multi-tenant
 *   Web Servers" (高集積マルチテナント Web サーバの大規模証明書管理),
 *   IPSJ SIG Technical Report, 2017.
 *   https://rand.pepabo.com/papers/iot37-proceeding-matsumotory.pdf
 *   (originally implemented for HTTP in ngx_mruby:
 *    https://github.com/matsumotory/ngx_mruby )
 *
 * Build: nginx ./configure --with-compat --with-mail --with-mail_ssl_module \
 *               --add-dynamic-module=/path/to/this/dir && make modules
 * Use:   load_module modules/ngx_mail_sni_module.so;  (main context)
 *        optional in mail{} or server{}: ssl_sni_certificates_path <dir>;
 *
 * License: BSD-2-Clause (same as nginx).
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_mail.h>
#include <ngx_mail_ssl_module.h>


/* not exported via a public header in some nginx versions */
extern ngx_module_t  ngx_mail_module;


typedef struct {
    ngx_str_t   path;       /* directory holding <servername>.{crt,key} */
} ngx_mail_sni_srv_conf_t;


static int ngx_mail_sni_certificate(ngx_ssl_conn_t *ssl_conn, void *arg);
static void *ngx_mail_sni_create_srv_conf(ngx_conf_t *cf);
static char *ngx_mail_sni_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_mail_sni_init_process(ngx_cycle_t *cycle);


static ngx_command_t  ngx_mail_sni_commands[] = {

    { ngx_string("ssl_sni_certificates_path"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_sni_srv_conf_t, path),
      NULL },

      ngx_null_command
};


static ngx_mail_module_t  ngx_mail_sni_module_ctx = {
    NULL,                              /* protocol */

    NULL,                              /* create main configuration */
    NULL,                              /* init main configuration */

    ngx_mail_sni_create_srv_conf,      /* create server configuration */
    ngx_mail_sni_merge_srv_conf        /* merge server configuration */
};


ngx_module_t  ngx_mail_sni_module = {
    NGX_MODULE_V1,
    &ngx_mail_sni_module_ctx,          /* module context */
    ngx_mail_sni_commands,             /* module directives */
    NGX_MAIL_MODULE,                   /* module type */
    NULL,                              /* init master */
    NULL,                              /* init module */
    ngx_mail_sni_init_process,         /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NGX_MODULE_V1_PADDING
};


/* Directory is captured at config time so the handshake callback (hot path,
 * no nginx conf access) can build the file path with plain libc.
 * Default applies when ssl_sni_certificates_path is not configured. */
static char  ngx_mail_sni_path[1024] = "/etc/nginx/certs/sni";


static int
ngx_mail_sni_certificate(ngx_ssl_conn_t *ssl_conn, void *arg)
{
    const char  *servername;
    u_char       crt[1300];
    u_char       key[1300];
    size_t       len, i;
    u_char       c;

    servername = SSL_get_servername(ssl_conn, TLSEXT_NAMETYPE_host_name);

    if (servername == NULL || *servername == 0) {
        return 1;   /* no SNI: keep the default certificate */
    }

    len = ngx_strlen(servername);
    if (len == 0 || len > 200) {
        return 1;
    }

    /* allow only safe host name characters to avoid path traversal */
    for (i = 0; i < len; i++) {
        c = (u_char) servername[i];
        if (!((c >= (u_char) 97 && c <= (u_char) 122)     /* a-z */
              || (c >= (u_char) 65 && c <= (u_char) 90)    /* A-Z */
              || (c >= (u_char) 48 && c <= (u_char) 57)    /* 0-9 */
              || c == (u_char) 46 || c == (u_char) 45)) {  /* . - */
            return 1;
        }
    }

    ngx_snprintf(crt, sizeof(crt), "%s/%s.crt%Z",
                 ngx_mail_sni_path, (u_char *) servername);
    ngx_snprintf(key, sizeof(key), "%s/%s.key%Z",
                 ngx_mail_sni_path, (u_char *) servername);

    if (access((char *) crt, R_OK) != 0 || access((char *) key, R_OK) != 0) {
        return 1;   /* no per-SNI certificate: use the default */
    }

    if (SSL_use_certificate_chain_file(ssl_conn, (char *) crt) != 1) {
        return 1;
    }

    if (SSL_use_PrivateKey_file(ssl_conn, (char *) key, SSL_FILETYPE_PEM) != 1) {
        return 1;
    }

    return 1;
}


static void *
ngx_mail_sni_create_srv_conf(ngx_conf_t *cf)
{
    ngx_mail_sni_srv_conf_t  *sscf;

    sscf = ngx_pcalloc(cf->pool, sizeof(ngx_mail_sni_srv_conf_t));
    if (sscf == NULL) {
        return NULL;
    }

    return sscf;
}


static char *
ngx_mail_sni_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_mail_sni_srv_conf_t  *prev = parent;
    ngx_mail_sni_srv_conf_t  *conf = child;
    size_t                    n;

    ngx_conf_merge_str_value(conf->path, prev->path, "");

    if (conf->path.len) {
        if (ngx_conf_full_name(cf->cycle, &conf->path, 1) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
        n = conf->path.len < sizeof(ngx_mail_sni_path) - 1
            ? conf->path.len : sizeof(ngx_mail_sni_path) - 1;
        ngx_memcpy(ngx_mail_sni_path, conf->path.data, n);
        ngx_mail_sni_path[n] = '\0';
    }

    return NGX_CONF_OK;
}


/* Register the SNI certificate callback on every mail server's SSL_CTX.
 * Done at worker start: by then all SSL_CTX are created and inherited. */
static ngx_int_t
ngx_mail_sni_init_process(ngx_cycle_t *cycle)
{
    ngx_mail_conf_ctx_t        *ctx;
    ngx_mail_core_main_conf_t  *cmcf;
    ngx_mail_core_srv_conf_t  **cscfp;
    ngx_mail_ssl_conf_t        *sslcf;
    ngx_uint_t                  i, n;

    ctx = (ngx_mail_conf_ctx_t *) cycle->conf_ctx[ngx_mail_module.index];
    if (ctx == NULL) {
        return NGX_OK;   /* no mail {} block */
    }

    cmcf = ctx->main_conf[ngx_mail_core_module.ctx_index];
    if (cmcf == NULL) {
        return NGX_OK;
    }

    cscfp = cmcf->servers.elts;
    n = 0;

    for (i = 0; i < cmcf->servers.nelts; i++) {
        sslcf = cscfp[i]->ctx->srv_conf[ngx_mail_ssl_module.ctx_index];

        if (sslcf != NULL && sslcf->ssl.ctx != NULL) {
            SSL_CTX_set_cert_cb(sslcf->ssl.ctx, ngx_mail_sni_certificate, NULL);
            n++;
        }
    }

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "ngx_mail_sni: registered SNI cert callback on %ui mail "
                  "server(s), path=%s", n, ngx_mail_sni_path);

    return NGX_OK;
}
