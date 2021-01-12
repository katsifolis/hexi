-- One-file-no-dependency-hex-editor-in-lua --

-- Abbrs and Statics--
ter = require "terminal"
util = require "util"

-- All colors in decimal
COLORS = {
	MAGENTA = 128,
	RED = 124,
	BLACK = 0,
	WHITE = 255,
	BLUE = 12,
	LIGHTBLUE = 14,
}

-- Fns --

function is_printable(ch)
	return true and (ch > 0x20 and ch < 0x7f) or false
end

-- drawing status (filename, percentage, cur_pos)
function draw_status_bar(term, o)
	term.cur_save()
	term.cur_n(999)
	term.cur_clr_ln()
	term.color(COLORS.BLACK, nil, 248)
	term.out(term.fln)
	term.cur_r(999)
	local str = "(" .. term.cur[1] .. "," .. term.cur[2] .. ")"
	term.cur_l(#str-1)
	term.out(str)
	term.color_reset()
	term.cur_restore()
end

-- Core Functions --

-- main loop

function loop()
	running = true
	drw     = false
	local opts = util.getopt(arg, "o")
	local offset = opts["o"] or 16
	ter:init_term(arg[1], tonumber(offset))
	local c = util.get_char()
	local buf = util.r_file(arg[1] or nil)
	draw_ui(ter, buf)
	draw_status_bar(ter, offset)
	local ch
	while running do
		if drw then draw_ui(ter, buf);draw_status_bar(ter, offset) drw=false end
		input(ter)
	end
	ter:free_term()
end

function input(term)

		local c = util.get_char()
		local ch = util.last_char(c())

		if ch == 'q' then 
			running = false
		elseif ch == 'j' then
			term.cur_d(1)
			term.cur[1] = term.cur[1] < term.size[1] and term.cur[1]+1 or term.cur[1]
		elseif ch == 'k' then 
			term.cur_u(1)
			term.cur[1] = term.cur[1] > 1 and term.cur[1]-1 or term.cur[1]
		elseif ch == 'h' then 
			term.cur_l(1) 
			term.cur[2] = term.cur[2] >= 1 and term.cur[2]-1 or term.cur[2]
		elseif ch == 'l' then 
			term.cur_r(1) 
			term.cur[2] = term.cur[2] <= term.size[2] and term.cur[2]+1 or term.cur[2]
		elseif ch == 'n' then
			term.cur_scrl_d()
			drw = true
			term.sx = term.sx + 1
		elseif ch == 'p' then
			term.cur_scrl_u()
			drw = true
			term.sx = term.sx - 1
		elseif ch == 'g' then 
			term.cur_reset();
			term.cur_r(12+(term.offset*2)) end
end


function draw_ui(term, buf)
	-- clearing
	-- address bar 
	local addr = ""
	for i = term.sx, term.size[1]-2+term.sx do
--	for i = 0, term.size[0]-2 do
		addr = string.format("%08X: " , i * (term.offset))
		term.color(COLORS.MAGENTA, 1)
		term.out(addr)
		term.cur_n(1)
	end
	term.cur_reset()
	term.cur_r(10)
	c = 0
	for i, v in ipairs(buf) do
		if i-1 == (term.size[1]-1) * term.offset then break end -- -1 for printing the status line
		if (i-1) % term.offset == 0 and i ~= 1 then
			term.cur_n(1)
			-- offest of address + : + two_spaces = 11
			-- and integer division must be applied to avoid floating number
			-- to be sent through the signal because it causes weird offsets
			term.cur_r(10)
		end

		if is_printable(v) then
			term.color(COLORS.BLUE,1)
			term.out(string.format("%02x", v))
			term.cur_save()
			term.cur_r((term.offset*2)-(c))
			term.out(string.char(v))
		else
			term.color(COLORS.WHITE, 1)
			term.out(string.format("%02x", v))
			term.cur_save()
			term.cur_r((term.offset*2)-(c))
			term.color(COLORS.LIGHTBLUE,1)
			term.out(".")
		end

		term.cur_restore()
		c = c+1 >= (term.offset) and 0 or c + 1
	end
	term.cur_reset()
	term.cur_r(12+(term.offset*2))
	term.cur_show()

end

loop()
