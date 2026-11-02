FROM php:5.6-cli

# The last PHP images that still shipped the mcrypt extension, rebuilt from
# Debian's archive so libmcrypt-dev installs. MTKey regenerates its mcrypt
# cross-language vectors with the real extension inside this container:
#
#   docker build -t mcrypt-php56 -f tools/mcrypt-php56.Dockerfile tools/
#   docker run --rm -v "$PWD:/work" -w /work mcrypt-php56 \
#     php tools/gen-mcrypt-vectors.php > tests/mcrypt-vectors.json
RUN sed -i 's/deb.debian.org/archive.debian.org/g; s/security.debian.org/archive.debian.org/g' \
      /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null || true; \
    sed -i '/stretch-updates/d' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null || true; \
    printf 'Acquire::Check-Valid-Until "false";\nAcquire::AllowInsecureRepositories "true";\n' \
      > /etc/apt/apt.conf.d/99archive; \
    apt-get update -qq && \
    apt-get install -y -qq --allow-unauthenticated libmcrypt-dev && \
    docker-php-ext-install mcrypt
