FROM rust:1.81-alpine3.20

WORKDIR /app

COPY . .

RUN apk add musl-dev
RUN cargo build --release

ENTRYPOINT [ "cargo", "run", "--release" ]

EXPOSE 3000/tcp
