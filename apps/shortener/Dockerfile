FROM node:20-alpine 
WORKDIR /app
COPY package*.json ./
RUN npm install
RUN chmod +x node_modules/.bin/*
COPY . ./
EXPOSE 5001
CMD ["npm","run","dev"]