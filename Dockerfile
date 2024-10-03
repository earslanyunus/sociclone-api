# Node.js 20 Alpine sürümünü temel imaj olarak kullan
FROM node:20-alpine

# Çalışma dizinini belirle
WORKDIR /app

# package.json ve package-lock.json dosyalarını kopyala
COPY package*.json ./

# Bağımlılıkları yükle
RUN npm ci --only=production

# TypeScript'i global olarak yükle
RUN npm install -g typescript

# Kaynak kodları kopyala
COPY . .

# TypeScript kodunu derle
RUN npm run build

# Uygulama için kullanılacak portu belirt
EXPOSE 3000

# Uygulamayı başlat
CMD ["npm", "start"]