# Reverse Proxy and Subfolder Deployment

WebSSH uses regular HTTP routes plus Socket.IO/WebSocket traffic. A reverse
proxy must preserve the public origin and support connection upgrades.

## Required application settings

For one trusted proxy layer:

```bash
CORS_ORIGINS=https://ssh.example.com
SESSION_COOKIE_SECURE=true
TRUSTED_PROXIES=1
```

`TRUSTED_PROXIES` is the number of trusted forwarding layers, not a Boolean.
Keep the WebSSH backend reachable only through those layers.

## Nginx at the domain root

```nginx
location / {
    proxy_pass http://webssh:5000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

## Traefik at the domain root

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.webssh.rule=Host(`ssh.example.com`)"
  - "traefik.http.routers.webssh.tls.certresolver=letsencrypt"
  - "traefik.http.services.webssh.loadbalancer.server.port=5000"
```

## Caddy at the domain root

```caddyfile
ssh.example.com {
    reverse_proxy webssh:5000
}
```

## Apache at the domain root

Apache httpd 2.4.47 or newer can proxy HTTP and WebSocket upgrades through
`mod_proxy_http`. Enable `mod_proxy`, `mod_proxy_http`, `mod_headers`, and
`mod_ssl`, then use a TLS virtual host such as:

```apache
<VirtualHost *:443>
    ServerName ssh.example.com

    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/ssh.example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/ssh.example.com/privkey.pem

    ProxyPreserveHost On
    RequestHeader set X-Forwarded-Proto "https"
    ProxyPass "/" "http://127.0.0.1:5000/" upgrade=websocket
    ProxyPassReverse "/" "http://127.0.0.1:5000/"
</VirtualHost>
```

Older Apache versions require `mod_proxy_wstunnel` and an explicit WebSocket
rule. Prefer a supported 2.4.47+ release so HTTP and upgrade traffic share the
same mapping.

## Serve WebSSH under a path prefix

For a public URL such as `https://server.example.com/webssh`, configure:

```bash
APPLICATION_ROOT=/webssh
TRUSTED_PROXIES=1
CORS_ORIGINS=https://server.example.com
SESSION_COOKIE_SECURE=true
```

The reverse proxy must strip `/webssh` before forwarding the request and send
the original prefix as `X-Forwarded-Prefix`.

### Nginx subfolder

```nginx
location /webssh/ {
    proxy_pass http://webssh:5000/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Prefix /webssh;
}
```

The trailing slash in both `location` and `proxy_pass` is intentional.

### Traefik subfolder

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.webssh.rule=Host(`server.example.com`) && PathPrefix(`/webssh`)"
  - "traefik.http.middlewares.webssh-strip.stripprefix.prefixes=/webssh"
  - "traefik.http.middlewares.webssh-prefix.headers.customrequestheaders.X-Forwarded-Prefix=/webssh"
  - "traefik.http.routers.webssh.middlewares=webssh-strip,webssh-prefix"
  - "traefik.http.services.webssh.loadbalancer.server.port=5000"
```

### Caddy subfolder

```caddyfile
server.example.com {
    handle_path /webssh/* {
        reverse_proxy webssh:5000 {
            header_up X-Forwarded-Prefix /webssh
        }
    }
}
```

### Apache subfolder

Use Apache httpd 2.4.47+ with `mod_alias`, `mod_proxy`, `mod_proxy_http`,
`mod_headers`, and `mod_ssl`. This is a complete TLS virtual host; replace the
hostname and certificate paths for your installation:

```apache
<VirtualHost *:443>
    ServerName server.example.com
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/server.example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/server.example.com/privkey.pem

    ProxyRequests Off
    ProxyPreserveHost On
    ProxyAddHeaders On
    ProxyTimeout 3600
    RequestHeader unset X-Forwarded-For
    RequestHeader set X-Forwarded-Host "server.example.com"
    RequestHeader set X-Forwarded-Proto "https"
    RequestHeader set X-Forwarded-Prefix "/webssh"

    RedirectMatch permanent "^/webssh$" "/webssh/"
    ProxyPass "/webssh/" "http://127.0.0.1:5000/" upgrade=websocket timeout=3600
    ProxyPassReverse "/webssh/" "http://127.0.0.1:5000/"
</VirtualHost>
```

Apache adds the directly connected client address after removing untrusted
incoming forwarding values. This example assumes one proxy layer. Do not add
another catch-all `ProxyPass "/"` from the root example to this virtual host.

### HAProxy subfolder

This example terminates TLS at HAProxy and forwards to one WebSSH instance.
Use the application settings above and a PEM containing the certificate chain
and private key at the configured path. HTTP/1.1 supports both Socket.IO polling
and its WebSocket upgrade through the same backend:

```haproxy
global
    maxconn 1024

defaults
    mode http
    timeout connect 5s
    timeout client 60s
    timeout server 60s
    timeout tunnel 1h

frontend webssh_https
    bind :443 ssl crt /etc/haproxy/certs/server.example.com.pem alpn http/1.1
    acl webssh_bare path /webssh
    acl webssh_path path_beg /webssh/
    acl has_query query -m len gt 0
    http-request redirect code 308 location /webssh/?%[query] if webssh_bare has_query
    http-request redirect code 308 location /webssh/ if webssh_bare !has_query
    http-request deny deny_status 404 unless webssh_path
    default_backend webssh

backend webssh
    http-request set-header X-Forwarded-For %[src]
    http-request set-header X-Forwarded-Host %[req.hdr(Host)]
    http-request set-header X-Forwarded-Proto https
    http-request set-header X-Forwarded-Prefix /webssh
    http-request set-path %[path,regsub(^/webssh/,/)]
    server webssh 127.0.0.1:5000
```

`set-path` changes only the path; Socket.IO query parameters such as `EIO`,
`transport`, and `sid` remain intact. Do not replace the complete URI or route
WebSocket upgrades through a different prefix mapping. Forwarding headers are
overwritten because this example has exactly one trusted proxy layer.

For `/tools/webssh`, replace every `/webssh` prefix in the selected example
and set `APPLICATION_ROOT=/tools/webssh`. `CORS_ORIGINS` remains the public
origin without a path. `/webssh-other` is not part of `/webssh/`.

Start validation with exactly one Gunicorn `gthread` worker, as in the
Dockerfile. Keep the existing cookie and authentication settings. A working
health check alone does not establish that authenticated Socket.IO works.

These configurations must be syntax-checked against the installed proxy version
and verified with the authenticated checks below before deployment. References:
[Apache ProxyPass](https://httpd.apache.org/docs/2.4/mod/mod_proxy.html#proxypass)
and [HAProxy configuration manual](https://www.haproxy.com/documentation/haproxy-configuration-manual/latest/).

## Containerized proxy

When the proxy runs in Docker:

1. Attach WebSSH and the proxy to a private shared network.
2. Remove public port publishing from WebSSH.
3. Proxy to `webssh:5000` over the private network.
4. Set `TRUSTED_PROXIES` to the real number of trusted layers.

Do not publish `5000:5000` in parallel with the HTTPS proxy. That would allow
clients to bypass TLS and possibly the trusted-proxy boundary.

## WebSocket symptoms

If login works but terminal activity disconnects or never starts:

- confirm HTTP/1.1 on the upstream connection;
- confirm `Upgrade` and `Connection` forwarding;
- inspect browser network requests to `/socket.io/`;
- check that the proxy timeout accommodates long-lived connections;
- verify that the prefix is applied consistently for both HTTP and Socket.IO;
- verify `CORS_ORIGINS` exactly matches the browser-visible origin, including
  the scheme and non-default port.

## Trusted client addresses

WebSSH uses forwarded addresses only within the configured proxy trust depth.
An incorrect value can either record the proxy address instead of the client or
trust attacker-supplied forwarding headers. Prefer a simple topology and keep
the backend network private.

## Validation

```bash
curl -I https://ssh.example.com/
curl -fsS https://ssh.example.com/health
curl -fsS https://ssh.example.com/ready
```

For a subfolder:

```bash
curl -I https://server.example.com/webssh/
curl -fsS https://server.example.com/webssh/health
curl -fsS https://server.example.com/webssh/ready
```

Complete the check in a browser by logging in, opening a terminal, resizing it,
and transferring a small file.

### Authenticated transport diagnostics

Log in normally, then inspect the browser Network panel for the public path
`/webssh/socket.io/?EIO=4&transport=polling` (or your configured prefix). A
successful initial polling response starts with an Engine.IO open packet (`0`).
When upgrading, the WebSocket request should receive `101 Switching Protocols`.
An anonymous `curl` request can legitimately be rejected: WebSSH requires an
authenticated session before admitting an Engine.IO transport.

For a failed request, record the status, sanitized response text, transport,
timestamp, and matching server/proxy log event. A 404 can indicate a prefix
mapping error; a 400 can indicate an origin or protocol error; a 401 can indicate
an admission rejection. None of these codes alone proves the cause. Do not share
cookies, authorization headers, credentials, session IDs, or unredacted HAR files.

Check password, configured second factors and identity providers, session expiry
and return to the original page, terminal input/resize, upload/download, idle
connections and reconnect. Compare HTTP and Socket.IO scheme, host, prefix, and
client address. Record the WebSSH revision and proxy configuration with results.
