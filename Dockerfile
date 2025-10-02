# Baby Share Dockerfile
FROM node:18-alpine

# Set working directory inside container
WORKDIR /app

# Copy package.json and install dependencies first (cache layer)
COPY package*.json ./
RUN npm install --production

# Copy rest of the application
COPY . .

# Expose port (make sure it matches your .env PORT)
EXPOSE 3000

# Start the app
CMD ["node", "server.js"]
