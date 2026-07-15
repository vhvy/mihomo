#!/usr/bin/env bash
#
# build-image.sh — 从源码构建 mihomo Docker 镜像（可选推送）。
#
# 本脚本不含任何私密信息，可安全提交到公开仓库。
# registry / 命名空间 / 是否推送等全部通过环境变量传入，
# 本地使用和 GitHub Actions 共用同一份构建逻辑。
#
# 必需环境变量:
#   IMAGE      完整镜像名（不含 tag）
#
# 可选环境变量:
#   PUSH       true=构建后推送, 其它/未设=仅构建（默认 false）
#   EXTRA_TAG  额外附加的 tag（例如 nightly），默认空
#
# 前置条件:
#   - 已 docker login 到目标 registry（CI 里由 workflow 负责登录，
#     本地由你自己 docker login）
#
set -euo pipefail

: "${IMAGE:?请设置 IMAGE 环境变量，例如 registry/namespace/mihomo}"
PUSH="${PUSH:-false}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_DIR}"

# ---------- 生成标签与版本 ----------
COMMIT_HASH="$(git rev-parse --short HEAD)"
BUILD_DATE="$(date +%Y%m%d)"
TAG="${COMMIT_HASH}-${BUILD_DATE}"

BRANCH="$(git branch --show-current 2>/dev/null || echo "unknown")"
VERSION="${BRANCH:-unknown}-${COMMIT_HASH}"
BUILDTIME="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"

echo "========================================"
echo "  分支     : ${BRANCH}"
echo "  Commit   : ${COMMIT_HASH}"
echo "  版本     : ${VERSION}"
echo "  镜像     : ${IMAGE}:${TAG}"
echo "  构建时间 : ${BUILDTIME}"
echo "  Push     : ${PUSH}"
echo "========================================"

if ! command -v docker &>/dev/null; then
    echo "❌ 未找到 docker"
    exit 1
fi

# ---------- 组装 tag 参数 ----------
TAG_ARGS=(-t "${IMAGE}:${TAG}" -t "${IMAGE}:latest")
if [[ -n "${EXTRA_TAG:-}" ]]; then
    TAG_ARGS+=(-t "${IMAGE}:${EXTRA_TAG}")
fi

echo "📦 开始构建..."
docker build \
    -f "${PROJECT_DIR}/Dockerfile.self" \
    --build-arg VERSION="${VERSION}" \
    --build-arg BUILDTIME="${BUILDTIME}" \
    "${TAG_ARGS[@]}" \
    "${PROJECT_DIR}"

echo "✅ 构建成功: ${IMAGE}:${TAG}"

# ---------- 推送 ----------
if [[ "${PUSH}" == "true" ]]; then
    echo "🚀 推送镜像..."
    docker push "${IMAGE}:${TAG}"
    docker push "${IMAGE}:latest"
    [[ -n "${EXTRA_TAG:-}" ]] && docker push "${IMAGE}:${EXTRA_TAG}"
    echo "✅ 推送完成"
else
    echo "🔸 未推送（PUSH != true）。手动推送: docker push ${IMAGE}:${TAG}"
fi
