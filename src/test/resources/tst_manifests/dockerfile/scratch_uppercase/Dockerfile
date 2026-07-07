FROM node:18 AS builder

WORKDIR /app
RUN npm ci

FROM SCRATCH

COPY --from=builder /app/dist /
