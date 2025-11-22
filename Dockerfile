FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive


RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libsqlite3-dev \
    sqlite3

WORKDIR /app
COPY . .

RUN cmake . && make


EXPOSE 8080
CMD ["./authsrv.dir"]
