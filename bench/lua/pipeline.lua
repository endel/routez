-- 16 requests per write, so the server's response batching shows up.
local DEPTH = 16
local req
init = function(args)
    local parts = {}
    for i = 1, DEPTH do parts[i] = wrk.format(nil, wrk.path) end
    req = table.concat(parts)
end
request = function() return req end
