#!/bin/sh
# Optional login for the whole console. With BASIC_AUTH_USER and BASIC_AUTH_PASSWORD set, nginx asks for them
# before serving the page or proxying /api; without them the console is open (fine on localhost).
set -eu
if [ -n "${BASIC_AUTH_USER:-}" ] && [ -n "${BASIC_AUTH_PASSWORD:-}" ]; then
    umask 077
    printf '%s:{PLAIN}%s\n' "$BASIC_AUTH_USER" "$BASIC_AUTH_PASSWORD" > /etc/nginx/htpasswd
    # nginx workers run as the nginx user and must be able to read it
    chown "${NGINX_USER:-nginx}" /etc/nginx/htpasswd 2>/dev/null || chmod 644 /etc/nginx/htpasswd
    printf 'auth_basic "Threat Console";\nauth_basic_user_file /etc/nginx/htpasswd;\n' > /etc/nginx/auth.conf
    echo "basic auth: on for user $BASIC_AUTH_USER"
else
    printf 'auth_basic off;\n' > /etc/nginx/auth.conf
    echo "basic auth: off (set BASIC_AUTH_USER and BASIC_AUTH_PASSWORD to require a login)"
fi
if [ -z "${API_KEY:-}" ]; then
    echo "API_KEY is not set: the backend will reject every /api request" >&2
fi
