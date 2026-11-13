# Real ClamAV daemon with an offline demo signature DB (no freshclam needed).
FROM clamav/clamav:stable

COPY eicar.hdb /var/lib/clamav/eicar.hdb
COPY clamd.conf /etc/clamav/clamd.conf

# official image: skip freshclam so the stack starts fully offline
ENV CLAMAV_NO_FRESHCLAM=true
