-- vps_probe schema (initdb; runs only on first cluster init)

CREATE TABLE IF NOT EXISTS probe_sample (
    ts        TIMESTAMPTZ NOT NULL,
    src       TEXT        NOT NULL,
    dst       TEXT        NOT NULL,
    dst_addr  INET,
    proto     TEXT        NOT NULL,
    ip_ver    SMALLINT    NOT NULL,
    seq       INT,
    rtt_ms    INT,
    ok        BOOLEAN     NOT NULL,
    batch_ts  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (ts, src, dst, proto, ip_ver)
);

CREATE INDEX IF NOT EXISTS idx_probe_link_time
    ON probe_sample (src, dst, proto, ip_ver, ts DESC);

CREATE INDEX IF NOT EXISTS idx_probe_ts
    ON probe_sample (ts DESC);

CREATE INDEX IF NOT EXISTS idx_probe_batch
    ON probe_sample (batch_ts DESC);

-- convenience view: 1-minute aggregation per link/proto/ip_ver
CREATE OR REPLACE VIEW probe_link_1min AS
SELECT
    date_trunc('minute', ts)                                  AS bucket,
    src, dst, proto, ip_ver,
    count(*)                                                  AS sent,
    count(*) FILTER (WHERE ok)                                AS recv,
    (1 - count(*) FILTER (WHERE ok)::float / count(*)) * 100  AS loss_pct,
    min(rtt_ms) FILTER (WHERE ok)                             AS rtt_min,
    avg(rtt_ms) FILTER (WHERE ok)                             AS rtt_avg,
    max(rtt_ms) FILTER (WHERE ok)                             AS rtt_max,
    percentile_cont(0.5)  WITHIN GROUP (ORDER BY rtt_ms)
        FILTER (WHERE ok)                                     AS rtt_p50,
    percentile_cont(0.95) WITHIN GROUP (ORDER BY rtt_ms)
        FILTER (WHERE ok)                                     AS rtt_p95
FROM probe_sample
GROUP BY 1, 2, 3, 4, 5;

-- convenience view: 5-minute aggregation
CREATE OR REPLACE VIEW probe_link_5min AS
SELECT
    to_timestamp(floor(extract(epoch FROM ts) / 300) * 300)   AS bucket,
    src, dst, proto, ip_ver,
    count(*)                                                  AS sent,
    count(*) FILTER (WHERE ok)                                AS recv,
    (1 - count(*) FILTER (WHERE ok)::float / count(*)) * 100  AS loss_pct,
    min(rtt_ms) FILTER (WHERE ok)                             AS rtt_min,
    avg(rtt_ms) FILTER (WHERE ok)                             AS rtt_avg,
    max(rtt_ms) FILTER (WHERE ok)                             AS rtt_max,
    percentile_cont(0.5)  WITHIN GROUP (ORDER BY rtt_ms)
        FILTER (WHERE ok)                                     AS rtt_p50,
    percentile_cont(0.95) WITHIN GROUP (ORDER BY rtt_ms)
        FILTER (WHERE ok)                                     AS rtt_p95
FROM probe_sample
GROUP BY 1, 2, 3, 4, 5;
