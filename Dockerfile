# ============================
# 1. Builder: компиляция
# ============================
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

#hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Сборка prometheus-cpp
WORKDIR /tmp/build

RUN git clone --depth 1 --branch v1.3.0 https://github.com/jupp0r/prometheus-cpp.git

WORKDIR /tmp/build/prometheus-cpp

RUN cmake -B build -S . \
      -DCMAKE_BUILD_TYPE=Release \
      -DENABLE_PULL=ON \
      -DENABLE_PUSH=OFF \
      -DENABLE_COMPRESSION=OFF \
      -DENABLE_TESTING=OFF \
 && cmake --build build -j"$(nproc)" \
 && cmake --install build

# Сборка blockmon
WORKDIR /app

COPY blockmon.cpp .

RUN g++ -std=c++17 -O2 blockmon.cpp -o blockmon \
    -I/usr/local/include \
    -L/usr/local/lib \
    -lprometheus-cpp-pull -lprometheus-cpp-core -lpthread

# ============================
# 2. Runtime: образ
# ============================
FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

#hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib/libprometheus-cpp-* /usr/local/lib/

RUN ldconfig

COPY --from=builder /app/blockmon /usr/local/bin/blockmon

ENV DMESG_EXPORTER_STATE_DIR=/var/lib/blockmon_exporter \
    DMESG_EXPORTER_LISTEN_ADDR=0.0.0.0:9105

RUN mkdir -p "$DMESG_EXPORTER_STATE_DIR"

EXPOSE 9105

ENTRYPOINT ["/usr/local/bin/blockmon"]
