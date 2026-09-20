-- Asks for gzip, and counts the responses that came back without it. routez
-- serves uncompressed past its per-worker encoder cap (gzip.max_active), which
-- is faster than compressing, so a row that doesn't check this reads as a better
-- result than it is. The one-shot gate before the load cannot see it.
wrk.headers["Accept-Encoding"] = "gzip"

local uncompressed = 0
response = function(status, headers, body)
    local e = headers["Content-Encoding"] or headers["content-encoding"]
    if e ~= "gzip" then uncompressed = uncompressed + 1 end
end

local report = done
done = function(summary, latency, requests)
    report(summary, latency, requests)
    io.write(string.format('{"uncompressed":%d}\n', uncompressed))
end
