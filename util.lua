local util = {}

-- getopt, POSIX style command line argument parser
-- param arg contains the command line arguments in a standard table.
-- param options is a string with the letters that expect string values.
-- returns a table where associated keys are true, nil, or a string value.
-- The following example styles are supported
--   -a one  ==> opts["a"]=="one"
--   -bone   ==> opts["b"]=="one"
--   -c      ==> opts["c"]==true
--   --c=one ==> opts["c"]=="one"
--   -cdaone ==> opts["c"]==true opts["d"]==true opts["a"]=="one"
-- note POSIX demands the parser ends at the first non option
--      this behavior isn't implemented.

function getopt( arg, options )
	local tab = {}
	for k, v in ipairs(arg) do
		if string.sub( v, 1, 2) == "--" then
			local x = string.find( v, "=", 1, true )
			if x then tab[ string.sub( v, 3, x-1 ) ] = string.sub( v, x+1 )
			else      tab[ string.sub( v, 3 ) ] = true
			end
		elseif string.sub( v, 1, 1 ) == "-" then
			local y = 2
			local l = string.len(v)
			local jopt
			while ( y <= l ) do
				jopt = string.sub( v, y, y )
				if string.find( options, jopt, 1, true ) then
					if y < l then
						tab[ jopt ] = string.sub( v, y+1 )
						y = l
					else
						tab[ jopt ] = arg[ k + 1 ]
					end
				else
					tab[ jopt ] = true
				end
				y = y + 1
			end
		end
	end
	return tab
end

-- r_file returns a byte array of the specified binary given 
function r_file(flname)
	if not flname then p("Didn't provide any file"); os.exit(1) end

	local f = io.open(flname, "rb")
	if not f then p("Cannot open file"); os.exit(1) end

	-- Reading byte by byte the file
	local buf = {}
	local i = 1
	while true do 
		local b = f:read(1)
		if b ~= nil then
			b = string.byte(b)
			buf[i] = b
			f:seek("set", i) -- incrementing file pointer
			i = i + 1
		else
			return buf
		end
	end
end
-- sleep function with seconds
function sleep(n)  -- seconds
	local t0 = os.clock()
	while os.clock() - t0 <= n do end
end

function last_char(s)
    return string.match(s, "[^\128-\191][\128-\191]*$")
end

function get_char()
	return coroutine.wrap(function()
		local c
		while true do
			c = io.stdin:read(1)
			coroutine.yield(c)
		end
	end)
end


util = { getopt = getopt, r_file = r_file, sleep = sleep, last_char = last_char, get_char = get_char }
return util
