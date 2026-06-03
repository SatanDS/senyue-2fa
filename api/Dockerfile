FROM node:20-alpine

WORKDIR /app
COPY package.json server.js ./

ENV PORT=3000
ENV DATA_DIR=/data
EXPOSE 3000

CMD ["node", "server.js"]