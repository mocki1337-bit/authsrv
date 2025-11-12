FROM ubuntu:22.04

RUN apt update && apt install -y g++ cmake curl

WORKDIR /app
COPY . .

RUN cmake . && make

EXPOSE 8080
CMD ["./authsrv"]
