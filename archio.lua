-- One-file-no-dependency-hex-editor-in-lua --

-- Abbrs and Statics--

-- All colors in decimal
COLORS = {
	MAGENTA = 128,
	RED = 124,
	BLACK = 0,
	WHITE = 255,
	BLUE = 12,
	LIGHTBLUE = 14,
}

local clock, p, out = os.clock, print, io.write
local strf, byte, char, rep = string.format, string.byte, string.char, string.rep
local stty = "stty"
local ESC = 27

-- Ansi terminal table --

term = {
	-- fields
	size			= {0,0},
	cur			= {0,0},
	-- util
	out         = out,
	outf        = function (...) out(...); io.flush() end,
	setrawmode  = function ()    os.execute(stty .. " " .. "raw 2>/dev/null") end,
	setsanemode = function ()    os.execute(stty .. " " .. "sane") end,
	-- Raw calls
	clear       = function ()    out("\027[2J") end,
	color       = function (f, a, b)   out("\027[38;5;" .. f .. 
												      "m\027[48;"  .. (a or 5) .. ";" .. (b or 255) .. "m")end,
	-- Cursor calls
	cur_clr_ln  = function ()    out("\027[2K") end,
	cur_u		   = function (o)   out("\027[" .. o .. "A") end, -- up 
	cur_n		   = function (o)   out("\027[" .. o .. "E") end, -- next
	cur_d		   = function (o)   out("\027[" .. o .. "B") end, -- down
	cur_p		   = function (o)   out("\027[" .. o .. "F") end, -- previous 
	cur_l		   = function (o)   out("\027[" .. o .. "D") end, -- left
	cur_r		   = function (o)   out("\027[" .. o .. "C") end, -- right
	cur_reset   = function ()    out("\027[1;1H") end,		   -- resets position (1,1)
	cur_hide    = function ()    out("\027[?25l") end,
	cur_show    = function ()    out("\027[?25h") end,
	cur_save    = function ()    out("\0277") end,             -- saves cursor position
	cur_restore = function ()    out("\0278") end,             -- restores it

}

-- returns cursor position (line, column)
term.cur_rc = function()
	os.execute("stty cbreak </dev/tty >/dev/tty 2>&1")
	outf("\027[6n") -- reports cursor position in the form n;m line;column, it needs parsing local 
	local s = io.read(6)
	os.execute("stty -cbreak </dev/tty >/dev/tty 2>&1");
	os.execute("stty -echo raw 2>/dev/tty");
	term.cur_clr_ln()
	local lin, col = s:match("(%d+);(%d+)")
	if not lin then return nil end
	return tonumber(lin), tonumber(col)
end

-- returns the ternminal's dimensions
term.scr_dim = function() 
	term.cur_save()
	term.cur_d(999)
	term.cur_r(999)
	lin, col = term.cur_rc()
	term.cur_restore()
	return lin, col
end

function init_term()
	term.size[0], term.size[1] = term.scr_dim()
	term.cur[0], term.cur[1] = 1, 1
	term.setrawmode()
	term.cur_reset()
	term.clear()
end

function free_term()
	term.cur_reset()
	term.cur_show()
	term.setsanemode()
end

-- Fns --

function is_printable(ch)
	return true and (ch > 0x20 and ch < 0x7f) or false
end

function outf(...)
	io.write(...);io.flush()
end

-- sleep function with seconds
function sleep(n)  -- seconds
	local t0 = clock()
	while clock() - t0 <= n do end
end

function draw_status_bar()
	term.cur_n(999)
	term.cur_clr_ln()
	term.color(COLORS.BLACK, nil, 248)
	term.out("HELLO THERE")
end

-- Core Functions --

-- main loop
local function lastChar(s)
    return string.match(s, "[^\128-\191][\128-\191]*$")
end

function loop()
	local running = true
	local c = input()
	local buf = r_file(arg[1] or nil)
	draw_ui(16, buf)
	while running do
		ch = lastChar(c())
		if     ch == 'q' then running = false
		elseif ch == 'j' then term.cur_d(1) 
		elseif ch == 'k' then term.cur_u(1) 
		elseif ch == 'h' then term.cur_l(1) 
		elseif ch == 'l' then term.cur_r(1) end
	end
	free_term()
end

function input()
	return coroutine.wrap(function()
		local c
		while true do
			c = io.stdin:read(1)
			coroutine.yield(c)
		end
	end)
end

function draw_ui(o, buf)
	-- clearing
	init_term()
	-- address bar 
	local addr = ""
	for i=0, term.size[0]-2 do
		addr =string.format("%08X: " , i * (o))
		term.color(COLORS.MAGENTA, 1)
		term.out(addr)
		term.cur_n(1)
	end
	term.cur_reset()
	term.cur_r(10)
	c = 0
	for i, v in ipairs(buf) do
		if i-1 == (term.size[0]-1) * o then break end -- -1 for printing the status line
		if (i-1) % o == 0 and i ~= 1 then
			term.cur_n(1)
			-- offest of address + : + two_spaces = 11
			-- and integer division must be applied to avoid floating number
			-- to be sent through the signal because it causes weird offsets
			term.cur_r(10)
		end

		if is_printable(v) then
			term.color(COLORS.BLUE,1)
			term.out(strf("%02x", v))
			term.cur_save()
			term.cur_r((o*2)-(c))
			term.out(char(v))
		else
			term.color(COLORS.WHITE, 1)
			term.out(strf("%02x", v))
			term.cur_save()
			term.cur_r((o*2)-(c))
			term.color(COLORS.LIGHTBLUE,1)
			term.out(".")
		end

		term.cur_restore()
		c = c+1 >= (o) and 0 or c + 1
	end
	term.cur_reset()
	term.cur_r(12+(o*2))
	term.cur_show()

--	draw_status_bar()

	-- flushing, waiting, freeing term
	--io.flush()
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
			b = byte(b)
			buf[i] = b
			f:seek("set", i) -- incrementing file pointer
			i = i + 1
		else
			return buf
		end
	end
end

loop()
