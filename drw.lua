local drw = {}
local f    = string.format
local char = string.char

local function draw_ui(term)
   local addr
   local c = 0
   local hx
   local as
   local ascii_pos = 51
   local s_idx = term.sx * term.offset
   local e_idx = (term.size[1]-2+term.sx) * term.offset

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
   -- Is in first line
   for i = s_idx, e_idx do
      hx = f("%02x", term.hex[i-term.offset+1] or 0x3e8)
      as = char(term.ascii[i-term.offset+1] or 0x20)
      if i % term.offset == 0  then
         term.cur_n(1)
         -- offset of address + : + two_spaces = 11
         -- and integer division must be applied to avoid floating number
         -- to be sent through the signal because it causes weird offsets
         term.cur_r(10)
      end
      term.color(COLORS.BLUE,1)
      if i % 2 == 0 and i % 16 ~= 0 then
         term.out(" ")
      end
      term.out((hx == "3e8") and "  " or hx)
      term.cur_save()
      term.cur_l(999)
      term.cur_r(ascii_pos+c)
      term.out(as)
      term.cur_restore()
      c = c+1 >= (term.offset) and 0 or c + 1 -- correcting the offset
   end
   term.cur_reset()
   -- BASED indexing: initially offset was 12 but indexing starts at 1 for lua so subtract 1.
   term.cur_r(ascii_pos+term.cur[2]-1) -- cause everything is indexed by 1 
   term.cur_d(term.cur[1])
   term.cur_show()
end

-- drawing status (filename, percentage, cur_pos)
local function draw_status_bar(term)
   local v, p, d, h
   term.cur_save()
   term.cur_n(999)
   term.cur_clr_ln()
   term.color(COLORS.WHITE, 1)
   term.out(term.fln)
   term.out("(" .. tostring(#term.buffer) .. " bytes" .. ")")
   term.cur_r(999)
   v = (term.offset*(term.cur[1]-1)) + term.cur[2] + ((term.sx-1)*term.offset) -- value
   p = f(" - %.f%%", (v * 100) / (#term.buffer))                               -- percent
   d = f("%d", v)                                                              -- decimal  
   h = f("0x%08x", v)                                                          -- hex
   term.cur_l(#d+#h+#p) -- Calculating the amount of backstepping to print until the edge of screen
   term.out(h .. "," .. d .. p)
   term.color_reset()
   term.cur_restore()
end

local function draw_top_bar(term, interval)
   term.cur_save()
   term.cur_reset()
end

drw = {draw_ui = draw_ui, draw_status_bar = draw_status_bar, draw_top_bar = draw_top_bar}
return drw
