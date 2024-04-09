FROM golang:1.21.8-alpine3.19 as builder

WORKDIR /zauthn

COPY go.mod go.sum ./
RUN go mod download

COPY ./app .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o bin .

FROM scratch

COPY --from=builder /zauthn/bin /zauthn
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ENV ZAUTHN_PRIVATE_KEY_FILE  "/zauthn.d/key.json"
ENV ZAUTHN_WID_TOKEN_FILE "/wid/token"
ENV ZAUTHN_TOKEN_REFRESH_LEAD_TIME "15m"

CMD ["/zauthn"]