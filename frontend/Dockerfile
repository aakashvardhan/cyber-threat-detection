# Threat Console frontend: React build served by nginx, which also proxies /api to the backend.
# The API key is NOT baked into the JavaScript: nginx adds it on the server side (API_KEY at run time).
#   docker build -t threat-console-frontend .
#   docker run -p 8080:80 -e API_KEY=... -e BACKEND_URL=http://backend:8000 threat-console-frontend
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
# same-origin API through the nginx proxy; no key in the bundle
ENV VITE_API_BASE_URL=/api VITE_API_KEY=
RUN npm run build

FROM nginx:1.27-alpine
ENV BACKEND_URL=http://backend:8000 API_KEY=
COPY nginx/default.conf.template /etc/nginx/templates/default.conf.template
COPY nginx/15-basic-auth.sh /docker-entrypoint.d/15-basic-auth.sh
RUN rm -f /etc/nginx/conf.d/default.conf && chmod +x /docker-entrypoint.d/15-basic-auth.sh
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
# /healthz is exempt from the login, so the check works with basic auth on
HEALTHCHECK --interval=15s --timeout=3s CMD wget -qO- http://localhost/healthz >/dev/null || exit 1
