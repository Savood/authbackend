FROM golang:1.10-alpine as builder

RUN apk add --no-cache make gcc musl-dev linux-headers git

WORKDIR /go/src/git.dhbw.chd.cx/savood/authbackend
COPY . .

RUN go get -d -v ./...
RUN go install -v ./...



FROM alpine:latest

RUN apk add --no-cache ca-certificates
COPY --from=builder /go/bin/authbackend /usr/local/bin/

WORKDIR /opt/authbackend

EXPOSE 8080
CMD ["authbackend"]