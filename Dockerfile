FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p rbacscope

FROM scratch
COPY --from=build /src/target/release/rbacscope /rbacscope
USER 65532:65532
ENTRYPOINT ["/rbacscope"]
