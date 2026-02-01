FROM node:20-alpine 
WORKDIR /app
COPY package*.json ./
RUN npm install
RUN chmod +x node_modules/.bin/ts-node-dev
COPY . ./
EXPOSE 5001
CMD ["npm","run","dev"]