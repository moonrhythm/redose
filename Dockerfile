FROM golang:1.14.4-alpine as build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o redose -ldflags "-w -s" ./cmd/redose/main.go

FROM alpine:3.11

RUN apk add --no-cache tzdata
COPY --from=build /src/redose /usr/local/bin/redose

EXPOSE 6379
ENTRYPOINT ["redose"]
