FROM karalabe/xgo-latest

RUN \
  apt-get update && apt-get install -y libpcap-dev --no-install-recommends