-- The file's own Last-Modified, substituted by bench.sh: nginx compares the
-- date exactly, so a future one would get a 200 from it and a 304 from routez.
wrk.headers["If-Modified-Since"] = "IMS_DATE"
