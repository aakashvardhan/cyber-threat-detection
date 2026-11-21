# Threat Console frontend: React build served by nginx. Build from frontend/:
#   docker build -t threat-console-frontend --build-arg VITE_API_BASE_URL=http://localhost:8000 --build-arg VITE_API_KEY=... .
# Vite bakes these values into the JavaScript at build time; rebuild the image to change them.
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
ARG VITE_API_BASE_URL=http://localhost:8000
ARG VITE_API_KEY=
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL VITE_API_KEY=$VITE_API_KEY
RUN npm run build

FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
HEALTHCHECK --interval=15s --timeout=3s CMD wget -qO- http://localhost/ >/dev/null || exit 1
