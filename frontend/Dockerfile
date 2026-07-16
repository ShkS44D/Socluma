FROM node:22-slim

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies with clean install
RUN npm install -g npm@11.6.2
RUN npm ci

# Copy project
COPY . .

# Expose port
EXPOSE 3000

# Run dev server
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
