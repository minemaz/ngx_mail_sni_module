# ngx_mail_sni_module

**SNI-based dynamic TLS certificate selection for the nginx mail proxy
(IMAP / POP3 / SMTP) — including STARTTLS.**

A loadable nginx **dynamic module** (no core patch, no nginx rebuild) that lets
a single nginx mail proxy present a **different certificate per hostname (SNI)**
on a shared IP / port — the same thing the `http` and `stream` modules already
do, but which the stock **mail** module does not support.

It works for **STARTTLS** ports (143/110/587) as well as implicit-TLS ports
(993/995/465).

## Why

nginx's `http` and `stream` modules select the certificate by the TLS SNI host
name. The **mail** module does **not**: it binds one certificate to the
listening socket, so two server blocks on the same `listen` are rejected
(`duplicate ... address and port pair`) and `ssl_certificate` does not accept
variables. On a shared IP, a client connecting as `mail.b.example` to a proxy
configured with `mail.a.example`'s certificate gets a name-mismatch and refuses
to connect.

This is an **nginx implementation limitation, not a protocol one**. The TLS SNI
extension is present in the ClientHello — and for STARTTLS, the ClientHello is
sent *after* the `STARTTLS` command, so the SNI is still available to the
server. Real mail servers already use it (Dovecot `local_name`, Postfix
`tls_server_sni_maps`).

## How it works

At worker start the module walks every mail server's `SSL_CTX` and registers an
OpenSSL certificate callback via `SSL_CTX_set_cert_cb()`. During the TLS
handshake the callback reads the SNI host name and loads

```
<ssl_sni_certificates_path>/<servername>.crt   (full chain)
<ssl_sni_certificates_path>/<servername>.key
```

with `SSL_use_certificate_chain_file()` / `SSL_use_PrivateKey_file()`. If there
is no matching file it returns without changing anything, so nginx falls back to
the certificate configured with the normal `ssl_certificate` directive.

Because the certificate is chosen *during the handshake*, it also covers
STARTTLS (which L4 SNI routing such as `stream` `ssl_preread` cannot, since the
connection starts in plaintext).

The technique — dynamic certificate loading at the TLS handshake via
`SSL_CTX_set_cert_cb()` — is taken from the work cited under
[Acknowledgments](#acknowledgments) below.

## Build

The module needs to be ABI-compatible with your nginx. Build it against the
**same nginx version** configured with `--with-compat`:

```sh
NGINX_VERSION=1.30.2
curl -O https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz
tar xzf nginx-${NGINX_VERSION}.tar.gz
cd nginx-${NGINX_VERSION}
./configure --with-compat --with-mail --with-mail_ssl_module \
            --add-dynamic-module=/path/to/ngx_mail_sni_module
make modules
# -> objs/ngx_mail_sni_module.so
```

A `Dockerfile` is included that builds the `.so` against the official
`nginx:stable` image's version and produces a ready-to-load module.

## Usage

```nginx
# main context (top of nginx.conf)
load_module modules/ngx_mail_sni_module.so;

mail {
    # directory with <servername>.crt / <servername>.key per SNI host.
    # default: /etc/nginx/certs/sni   (relative paths resolve under the conf prefix)
    ssl_sni_certificates_path /etc/nginx/certs/sni;

    # the usual ssl_certificate is the fallback for unknown / no SNI
    ssl_certificate     /etc/nginx/certs/default.crt;
    ssl_certificate_key /etc/nginx/certs/default.key;

    server {
        listen   143;
        protocol imap;
        starttls on;
        # ... auth_http, proxy_pass etc.
    }
    server {
        listen   993 ssl;
        protocol imap;
    }
    # ... pop3 / smtp servers
}
```

Place per-host certificates as:

```
/etc/nginx/certs/sni/mail.a.example.crt    # full chain (PEM)
/etc/nginx/certs/sni/mail.a.example.key    # private key (PEM)
/etc/nginx/certs/sni/mail.b.example.crt
/etc/nginx/certs/sni/mail.b.example.key
```

Adding or renewing a host certificate needs **no nginx reload** — the callback
reads the file on every handshake. (Changing the fallback `ssl_certificate`
does need a reload, as usual.)

### Directive

| Directive | Context | Default | Description |
|---|---|---|---|
| `ssl_sni_certificates_path <dir>` | mail, server | `/etc/nginx/certs/sni` | Directory holding `<servername>.{crt,key}`. |

## Notes / security

- The nginx worker (e.g. user `nginx`) must be able to **read the key files**;
  on a per-handshake `access()` failure the module silently uses the fallback
  certificate. Keep the directory itself protected and the keys readable by the
  worker.
- The SNI host name is validated (`a-z A-Z 0-9 . -`, max 200 chars) before being
  used in a path, to prevent path traversal.
- Verified on nginx 1.30.x with OpenSSL 3.x for IMAP/POP3/SMTP on
  143/993/110/995/587/465 (STARTTLS and implicit TLS).

## Acknowledgments

This module is a direct application of the idea presented in the following paper,
which introduced **dynamic server-certificate selection at the TLS handshake via
OpenSSL's `SSL_CTX_set_cert_cb()`** (implemented there for HTTP in
[`ngx_mruby`](https://github.com/matsumotory/ngx_mruby)). This module brings the
same idea to the nginx **mail** module in plain C:

> 松本 亮介, 三宅 悠介, 力武 健次, 栗林 健太郎,
> 「高集積マルチテナント Web サーバの大規模証明書管理」
> (Ryosuke Matsumoto, Yusuke Miyake, Kenji Rikitake, Kentaro Kuribayashi,
> *"Large-scale Certificate Management on Highly-integrated Multi-tenant Web
> Servers"*), 情報処理学会研究報告 (IPSJ SIG Technical Report), 2017.
>
> Paper: https://rand.pepabo.com/papers/iot37-proceeding-matsumotory.pdf

With gratitude to the authors for the technique. Any bugs here are mine, not
theirs.

## License

BSD-2-Clause (same as nginx). See `LICENSE`.
