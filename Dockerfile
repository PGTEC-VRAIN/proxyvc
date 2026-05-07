# Use official Node.js runtime as base image
FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies
RUN npm ci --omit=dev

# Copy the proxy logic
COPY proxy.js .
COPY wallet-identity ./wallet-identity

# Expose the port
EXPOSE 8090

# Health check (optional but recommended)
# We hit the root path directly to check if the proxy is responding
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:8090/', (r) => { if (r.statusCode !== 404 && r.statusCode !== 200 && r.statusCode !== 502) throw new Error(r.statusCode) })" || exit 1

# Run the application
CMD ["node", "proxy.js"]