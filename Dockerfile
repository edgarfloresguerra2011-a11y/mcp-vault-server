FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json tsconfig.json ./
RUN npm ci --ignore-scripts
COPY src ./src
RUN npm run build

# FIX M-8: Imagen distroless fijada por digest para evitar supply chain attacks
# Para actualizar: docker pull gcr.io/distroless/nodejs20-debian12:nonroot y obtener nuevo digest
# Verificar en: https://github.com/GoogleContainerTools/distroless
FROM gcr.io/distroless/nodejs20-debian12:nonroot@sha256:48536b3a3c8a91eac83d694ef4c6a5f7e57b1e9fb7c8c04093c05e2edf9498be

WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json

USER nonroot
EXPOSE 8080
ENV NODE_ENV=production PORT=8080 TRANSPORT=http
CMD ["dist/index.js"]
