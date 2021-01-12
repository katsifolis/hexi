local term = {}
term.__index = term

setmetatable(term, {
	__call = function (cls, ...)
		return cls.new(...)
	end,
})

function term:new()
	local self = setmetatable({}, term)
	return self
end


term = {
	-- fields
	fln			= "",    -- filename
	size			= {0,0}, -- size of the terminal
	cur			= {0,0}, -- cursor position
	offset      = 0,     -- octet offset
	sx          = 0,     -- scroll offset
	-- util
	out         = function (...) io.write(...) end,
	setrawmode  = function ()          os.execute("stty " .. "raw 2>/dev/null") end,
	setsanemode = function ()          os.execute("stty " .. "sane") end,
	-- Raw calls
	clear       = function ()          io.write("\027[2J") end,
	color_reset = function ()          io.write("\027[0m") end,
	color       = function (f, a, b)   io.write("\027[38;5;" .. f ..  "m\027[48;"  .. (a or 5) .. ";" .. (b or 255) .. "m")end,
	-- Cursor calls
	cur_clr_ln  = function ()    		  io.write("\027[2K") end,
	cur_n		   = function (o)   		  io.write("\027[" .. o .. "E")end, -- next
	cur_p		   = function (o)   		  io.write("\027[" .. o .. "F")end, -- previous 
	cur_u		   = function (o)   		  io.write("\027[" .. o .. "A")end, -- up 
	cur_d		   = function (o)   		  io.write("\027[" .. o .. "B")end, -- down
	cur_l		   = function (o)   		  io.write("\027[" .. o .. "D")end, -- left
	cur_r		   = function (o)   		  io.write("\027[" .. o .. "C")end, -- right
	cur_scrl_u  = function ()          io.write("\027[1T")end,   
	cur_scrl_d  = function ()          io.write("\027[1S")end,
	cur_reset   = function ()    		  io.write("\027[1;1H") end,		   -- resets position (1,1)
	cur_hide    = function ()    		  io.write("\027[?25l") end,
	cur_show    = function ()    		  io.write("\027[?25h") end,
	cur_save    = function ()    		  io.write("\0277") end,             -- saves cursor position
	cur_restore = function ()    		  io.write("\0278") end,             -- restores it

}

-- returns cursor position (line, column)
function term:cur_rc()
	os.execute("stty cbreak </dev/tty >/dev/tty 2>&1")
	io.write("\027[6n") -- reports cursor position in the form n;m line;column, it needs parsing local 
	local s = io.read(6)
	os.execute("stty -cbreak </dev/tty >/dev/tty 2>&1");
	os.execute("stty -echo raw 2>/dev/tty");
	self:cur_clr_ln()
	local lin, col = s:match("(%d+);(%d+)")
	if not lin then return nil end
	return tonumber(lin), tonumber(col)
end

-- returns the ternminal's dimensions
function term:scr_dim()
	self.cur_save()
	self.cur_d(999)
	self.cur_r(999)
	self.cur_l(1)
	lin, col = self:cur_rc()
	self.cur_restore()
	return lin, col
end

function term:init_term(argv, off)
	self.fln = argv
	self.offset = off
	self.size[1], self.size[2] = self:scr_dim()
	self.cur[1], self.cur[2] = 1, 1
	self.setrawmode()
	self.cur_reset()
	self.clear()
end

function term:free_term()
	self.cur_reset()
	self.cur_show()
	self.color_reset()
	self.clear()
	self.setsanemode()
end


return term
