# Stage 1: Build production React + Vite application
FROM node:20-alpine AS builder

WORKDIR /app

# Copy dependency manifests
COPY frontend/package.json frontend/package-lock.json* ./

# Install dependencies cleanly
RUN npm ci || npm install

# Copy source code and build
COPY frontend/ ./
RUN npm run build

# Stage 2: Serve production assets via Nginx
FROM nginx:1.27-alpine AS runner

# Security: Remove default Nginx welcome page
RUN rm -rf /usr/share/nginx/html/*

# Copy built distribution from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Provide standard internal SPA configuration
RUN echo 'server { \
    listen 80; \
    server_name localhost; \
    root /usr/share/nginx/html; \
    index index.html; \
    location / { \
        try_files $uri $uri/ /index.html; \
    } \
    location /assets/ { \
        expires 1y; \
        add_header Cache-Control "public, immutable"; \
    } \
}' > /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -q --spider http://localhost:80/ || exit 1

CMD ["nginx", "-g", "daemon off;"]

