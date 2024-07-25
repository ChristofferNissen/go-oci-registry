FROM golang:1.19 AS build

WORKDIR /build

COPY . /build

RUN CGO_ENABLED=0 go build -o registry

FROM gcr.io/distroless/base-debian11:nonroot

COPY --from=build /build/registry /bin/registry

ENTRYPOINT ["/bin/registry"]
