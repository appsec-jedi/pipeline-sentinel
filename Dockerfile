FROM golang:1.23-bookworm AS builder
WORKDIR /src
RUN apt-get update && apt-get install -y clang llvm libbpf-dev make bpftool
COPY . .
RUN make

FROM ubuntu:22.04
RUN mkdir -p /app/reports
WORKDIR /app
RUN apt-get update && apt-get install -y curl python3
COPY --from=builder /src/pipeline-sentinel /usr/local/bin/pipeline-sentinel
COPY fake_build_script.sh /app/fake_build_script.sh
COPY rules.yaml /app/rules.yaml

ENTRYPOINT ["pipeline-sentinel"]