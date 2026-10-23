# SPDX-License-Identifier: Apache-2.0
#
# The Edicta tools image of the local dev stack: edictad, edicta and
# edicta-devinit, built with the edictadev tag. DEV ONLY: do not publish this
# image or run it against a public chain.
#
# Build context is the repository root:
#   docker build -f deploy/dev/Dockerfile .

FROM golang:1.26.8-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS build
ENV GOTOOLCHAIN=local CGO_ENABLED=0
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go -C celestia build -trimpath -tags edictadev -o /out/ ./cmd/edictad && \
    go -C services/cli build -trimpath -tags edictadev -o /out/ \
      ./cmd/edicta ./cmd/edicta-devinit

FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
COPY --from=build /out/ /usr/local/bin/
LABEL org.opencontainers.image.description="Edicta dev tools. DEV ONLY."
