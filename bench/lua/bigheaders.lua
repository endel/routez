-- What a logged-in browser actually sends: ~1.5 KB of headers, most of it
-- cookies, so the row measures header parsing rather than the response.
wrk.headers["User-Agent"] =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) " ..
    "Chrome/141.0.0.0 Safari/537.36"
wrk.headers["Accept"] =
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
wrk.headers["Accept-Language"] = "en-GB,en-US;q=0.9,en;q=0.8,pt-BR;q=0.7"
wrk.headers["Accept-Encoding"] = "gzip, deflate, br, zstd"
wrk.headers["Cache-Control"] = "no-cache"
wrk.headers["Sec-Ch-Ua"] = '"Chromium";v="141", "Not=A?Brand";v="24"'
wrk.headers["Sec-Fetch-Dest"] = "document"
wrk.headers["Sec-Fetch-Mode"] = "navigate"
wrk.headers["Sec-Fetch-Site"] = "same-origin"
wrk.headers["Upgrade-Insecure-Requests"] = "1"
local jar = {}
for i = 1, 12 do
    jar[i] = string.format("sid%02d=%s", i, string.rep(string.char(97 + i % 26), 80))
end
wrk.headers["Cookie"] = table.concat(jar, "; ")
