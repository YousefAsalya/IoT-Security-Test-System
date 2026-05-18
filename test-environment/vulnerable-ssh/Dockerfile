FROM alpine:3.19

RUN apk add --no-cache openssh bash

RUN ssh-keygen -A && \
    echo "root:toor"    | chpasswd && \
    adduser -D -s /bin/sh admin && \
    echo "admin:admin"  | chpasswd && \
    adduser -D -s /bin/sh pi && \
    echo "pi:raspberry" | chpasswd

COPY sshd_config /etc/ssh/sshd_config
RUN echo "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6" > /etc/ssh/banner.txt

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
