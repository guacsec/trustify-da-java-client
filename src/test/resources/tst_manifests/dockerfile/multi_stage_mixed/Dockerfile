ARG BASE=ubuntu:22.04
FROM ${BASE} AS base

RUN apt-get update

FROM node:18 AS builder

WORKDIR /app
COPY . .
RUN npm ci && npm run build

FROM scratch AS empty

COPY --from=builder /app/dist /dist

FROM nginx:alpine

COPY --from=builder /app/dist /usr/share/nginx/html
