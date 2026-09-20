-- 1 MB uploaded per request: the row measures the body path, not the response.
wrk.method = "POST"
wrk.body = string.rep("x", 1024 * 1024)
wrk.headers["Content-Type"] = "application/octet-stream"
