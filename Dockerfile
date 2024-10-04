FROM oven/bun:debian

WORKDIR /app

COPY package.json  ./

RUN npm install

COPY . .

EXPOSE 3000

CMD ["bun", "src/app.ts"]