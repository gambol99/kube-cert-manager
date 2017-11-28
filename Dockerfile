FROM alpine:3.6

RUN apk --no-cache add ca-certificates && \
    adduser -D controller

ADD kube-cert-manager /kube-cert-manager

USER controller

ENTRYPOINT ["/kube-cert-manager"]
