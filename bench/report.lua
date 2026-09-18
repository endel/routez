-- Appends the run to wrk's output as one JSON line for report.py. Only
-- done() is defined: per-request hooks would slow wrk down.
done = function(summary, latency, requests)
    local e = summary.errors
    io.write(string.format(
        '{"requests":%d,"duration_us":%d,"bytes":%d,"p50_us":%d,"p99_us":%d,' ..
        '"connect":%d,"read":%d,"write":%d,"status":%d,"timeout":%d}\n',
        summary.requests, summary.duration, summary.bytes,
        latency:percentile(50), latency:percentile(99),
        e.connect, e.read, e.write, e.status, e.timeout))
end
