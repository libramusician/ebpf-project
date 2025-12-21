FROM nginx:latest AS base

FROM base AS server1
RUN echo server1 > /usr/share/nginx/html/index.html

FROM base AS server2
RUN echo server2 > /usr/share/nginx/html/index.html