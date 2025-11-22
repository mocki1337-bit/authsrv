FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    curl \
    ca-certificates \
    libcurl4-openssl-dev \
    libssl-dev \
    libsqlite3-dev \
    nlohmann-json3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Копируем весь проект
COPY . .

# Собираем в отдельной папке (чистая сборка)
RUN cmake -S . -B build \
    && cmake --build build --config Release -- -j$(nproc)

# Запускаемый файл окажется в build/
EXPOSE 8080

# Меняем на ваш исполняемый файл, если имя отличается — поправь
CMD ["./build/authsrv"]

