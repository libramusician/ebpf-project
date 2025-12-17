FROM nginx:latest
RUN apt update
RUN apt install net-tools
RUN apt install -y inetutils-ping