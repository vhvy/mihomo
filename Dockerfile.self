# 自用：从源码编译 mihomo 的多阶段 Dockerfile
# 官方 Dockerfile 依赖 CI 预编译好的二进制，不适合本地/自建，这里从源码直接编译。
# 本地与 GitHub Actions 共用此文件。

# ============ 阶段 1: 编译 ============
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates make

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION
ARG BUILDTIME

RUN CGO_ENABLED=0 go build -tags with_gvisor -trimpath \
    -ldflags "-X 'github.com/metacubex/mihomo/constant.Version=${VERSION}' \
              -X 'github.com/metacubex/mihomo/constant.BuildTime=${BUILDTIME}' \
              -w -s -buildid=" \
    -o /mihomo

# ============ 阶段 2: 下载 GeoIP/GeoSite 数据 ============
FROM alpine:latest AS geodata

RUN apk add --no-cache wget && \
    mkdir /mihomo-config && \
    wget -O /mihomo-config/geoip.metadb https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb && \
    wget -O /mihomo-config/geosite.dat  https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat && \
    wget -O /mihomo-config/geoip.dat    https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat

# ============ 阶段 3: 最终运行镜像 ============
FROM alpine:latest

# 指向本 fork 而非上游：镜像里带的是自有补丁（wireguard 入站），
# 溯源链接必须能找到实际构建用的源码。
LABEL org.opencontainers.image.source="https://github.com/vhvy/mihomo"

RUN apk add --no-cache ca-certificates tzdata iptables

VOLUME ["/root/.config/mihomo/"]

COPY --from=geodata /mihomo-config/ /root/.config/mihomo/
COPY --from=builder /mihomo /mihomo

ENTRYPOINT ["/mihomo"]
