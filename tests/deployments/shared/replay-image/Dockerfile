FROM busybox:1.36

COPY tests/deployments/shared/replay-image/replay-entrypoint.sh /usr/local/bin/replay-entrypoint.sh
COPY notes/log_example/access.log /fixtures/access.log

RUN chmod +x /usr/local/bin/replay-entrypoint.sh

ENV INPUT_FILE=/fixtures/access.log
ENV OUTPUT_FILE=/var/log/app/log.txt
ENV REPLAY_TO_STDOUT=false
ENV REPLAY_DONE_SLEEP_SECONDS=3600

ENTRYPOINT ["/usr/local/bin/replay-entrypoint.sh"]
