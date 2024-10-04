# Use a specific version of the official Node.js image as a base
FROM node:20-alpine

# Set the working directory in the container
WORKDIR /app

# Copy package.json and package-lock.json (if available)
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy all application files to the working directory
COPY . .

# Expose port 2001
EXPOSE 2001

# Command to run the Node.js server
CMD ["node", "server.js"]
