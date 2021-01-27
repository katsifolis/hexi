local drw = {}
local f    = string.format
local char = string.char

local function draw_ui(term)
   -- clearing
   -- address bar 
   local addr
   term.cur_hide()
   term.cur_reset()
   term.cur_n(1)

   for i=term.sx, term.size[1]-3+term.sx do
      term.color(COLORS.MAGENTA, 1)
      term.out(term.address[i])
      term.cur_n(1)
   end
   term.cur_reset()
   term.cur_r(10)
   local c = 0
   -- Is in first line
   local s_idx = term.sx * term.offset
   local e_idx = (term.size[1] - 2 + term.sx) * term.offset
   if e_idx > #term.buffer then
      e_idx = #term.buffer-50
   end
   for i = s_idx, e_idx do
      if i % term.offset == 0  then
         term.cur_n(1)
         -- offest of address + : + two_spaces = 11
         -- and integer division must be applied to avoid floating number
         -- to be sent through the signal because it causes weird offsets
         term.cur_r(10)
      end

      term.color(COLORS.BLUE,1)
      term.out(f("%02x", term.hex[i]))
      term.cur_save()
      term.cur_r((term.offset*2)-(c))
      term.out(char(term.ascii[i]))
      term.cur_restore()
      c = c+1 >= (term.offset) and 0 or c + 1 -- correcting the offset
   end
   term.cur_reset()
   -- BASED indexing: initially offset was 12 but indexing starts at 1 for lua so subtract 1.
   term.cur_r(11+(term.offset*2)+term.cur[2])
   term.cur_d(term.cur[1])
   term.cur_show()

end

-- drawing status (filename, percentage, cur_pos)
local function draw_status_bar(term)
   term.cur_save()
   term.cur_n(999)
   term.cur_clr_ln()
   term.color(COLORS.WHITE, 1)
   term.out(term.fln)
   term.cur_r(999)
   local str = "(" .. term.cur[1] .. "," .. term.cur[2] .. ")"
   term.cur_l(#str-1)
   term.out(str)
   term.color_reset()
   term.cur_restore()
end


drw = {draw_ui = draw_ui, draw_status_bar = draw_status_bar}
return drw
