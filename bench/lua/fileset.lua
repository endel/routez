-- One of 10k files per request, in a fixed pseudo-random order: the set is
-- larger than the open-file cache, so most requests miss it.
local COUNT = 10000
local reqs, n = {}, 0
init = function(args)
    math.randomseed(1)
    for i = 1, COUNT do
        reqs[i] = wrk.format(nil, string.format("%s%04d.bin", wrk.path, math.random(0, COUNT - 1)))
    end
end
request = function()
    n = n % COUNT + 1
    return reqs[n]
end
