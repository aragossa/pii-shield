FROM busybox:1.36

# Built from a staging context prepared by build_replay_image (common.sh):
# it contains replay-entrypoint.sh and the resolved access.log fixture
# (honoring PII_SHIELD_ACCESS_LOG), so no repo paths are referenced here.
COPY replay-entrypoint.sh /usr/local/bin/replay-entrypoint.sh
COPY access.log /fixtures/access.log

RUN chmod +x /usr/local/bin/replay-entrypoint.sh

ENV INPUT_FILE=/fixtures/access.log
ENV OUTPUT_FILE=/var/log/app/log.txt
ENV REPLAY_TO_STDOUT=false
ENV REPLAY_DONE_SLEEP_SECONDS=3600

ENTRYPOINT ["/usr/local/bin/replay-entrypoint.sh"]
