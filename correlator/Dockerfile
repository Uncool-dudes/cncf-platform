# syntax=docker/dockerfile:1.7
# The binary is cross-compiled on the host (`just correlator-image`), which
# avoids pulling a ~1GB golang builder image into a disk-constrained Docker VM.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --chown=nonroot:nonroot correlator /app/correlator
USER nonroot:nonroot
ENTRYPOINT ["/app/correlator"]
