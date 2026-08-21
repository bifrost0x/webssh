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

Enable `mod_alias` in addition to the modules used above. Redirect the missing
trailing slash and forward the public prefix explicitly:

```apache
RedirectMatch permanent "^/webssh$" "/webssh/"

<Location "/webssh/">
    RequestHeader set X-Forwarded-Prefix "/webssh"
</Location>

ProxyPass "/webssh/" "http://127.0.0.1:5000/" upgrade=websocket
ProxyPassReverse "/webssh/" "http://127.0.0.1:5000/"
```

Keep the trailing slash on both proxy paths. Set `APPLICATION_ROOT=/webssh` in
WebSSH as shown above.

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
