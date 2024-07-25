# OCI container registry in Go
This is a simple application implementing the [OCI image spec] &
[OCI distribution spec] for the purposes of education. This won't ever
be a production-grade registry but the goal is to have it pass all the OCI
distribution conformance tests as well as a playground to explore common
idioms and patterns in Go.

## High level objectives
* Implement the required [OCI distribution spec endpoints]
* [Use the image-spec schema] & [validate image-spec]
* Validate server using [distribution conformance tests]

[OCI image spec]: https://github.com/opencontainers/image-spec/blob/main/spec.md
[OCI distribution spec]: https://github.com/opencontainers/distribution-spec/blob/main/spec.md
[Use the image-spec schema]: https://github.com/opencontainers/image-spec/tree/main/specs-go/v1
[Validate image-spec]: https://github.com/opencontainers/image-spec/tree/main/schema
[distribution endpoints]: https://github.com/opencontainers/distribution-spec/blob/main/spec.md#endpoints
[distribution conformance tests]: https://github.com/opencontainers/distribution-spec/blob/main/conformance/README.md
