# Use official Node.js runtime as base image
FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies
RUN npm install --omit=dev

# Copy the proxy logic
COPY proxy.js .
COPY wallet-identity ./wallet-identity

# Expose the port
EXPOSE 8090

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:8090/__health', (r) => { if (r.statusCode !== 200) throw new Error(r.statusCode) })" || exit 1

# Run the application
CMD ["node", "proxy.js"]