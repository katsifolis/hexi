local util = require "util"
local drw  = require "drw"
-- input function
-- 1. send ansi command for move command
-- 2. check if within bounds
-- 3. draw status bar
local module = {}

local function input(term)

   local c = util.get_char()
   local o = #term.buffer%0x10==0 and 3 or 4 
   local ch = util.last_char(c())
   if ch == 'q' then 
      term.running = false
   -- Navigation
   elseif ch == 'j' then
      if (term.sx == term.limit + 1) and term.cur[2] > #term.buffer % 0x10 and term.cur[1] + 1 == term.size[1]-2 then 
      elseif (term.cur[1] <= term.size[1]-3) then
         term.cur_d(1)
         term.cur[1] = term.cur[1] < term.size[1] and term.cur[1]+1 or term.cur[1]
      elseif term.sx < term.limit then
         term.sx = term.sx + 1
         term.draw = true
      elseif term.sx == term.limit then
         term.cur[1], term.cur[2] = term.size[1]-2, #term.buffer % 16
         term.sx = term.sx + 1
         term.draw = true
      end
   elseif ch == 'k' then 
      if term.cur[1] > 1 then
         term.cur_u(1)
         term.cur[1] = term.cur[1] > 1 and term.cur[1]-1 or term.cur[1]
      else
         term.sx = term.sx > 1 and term.sx - 1 or term.sx
         term.draw = true
      end
   elseif ch == 'h' then 
      if term.cur[2] > 1 then 
         term.cur_l(1) 
         term.cur[2] = term.cur[2] >-  1 and term.cur[2]-1 or term.cur[2]
      end
   elseif ch == 'l' then 
      if term.cur[2] +1> #term.buffer % 0x10 and term.cur[1] == term.size[1]-2 and term.sx == term.limit +1 then
      elseif (term.cur[2] < term.offset) then
         term.cur_r(1) 
         term.cur[2] = term.cur[2]+1
      end
   -- next line
   elseif ch == 'n' then
      if term.sx-3 > (#term.buffer/0x10)-term.size[1] then return end
      term.sx = term.sx + 1
      term.draw = true

   -- previous line
   elseif ch == 'p' then -- previous line
      if term.sx <= 1 then return end
      term.sx = term.sx - 1
      term.draw = true

   -- resetting cursor to original position
   elseif ch == 'g' then
      term:cur_reset()
      term.cur[1], term.cur[2] = 1, 1
      term.sx = 1
      drw.draw_status_bar(term, offset)
      term.cur_r(12+(term.offset*2)) 
      term.cur_d(1)
      term.draw = true

   -- jump to the last byte
   elseif ch == 'G' then
      term.sx = (#term.buffer//0x10)-term.size[1]+o -- magic number 2 is first line and last line which is the status bar
      term.cur[1], term.cur[2] = term.size[1]-2, #term.buffer % 16
      term:cur_reset()
      term.draw = true

   -- computation of the element under the cursor position and increment
   elseif ch == ']' then
      local o       = term.cur[2]+((term.cur[1]-1)*term.offset+((term.sx-1)*term.offset))
      if term.ascii[o] < 255 then 
         term.ascii[o] = term.ascii[o] + 1
         term.hex[o]   = term.hex[o] + 1
         term.draw     = true
      end
   -- computation of the element under the cursor position and decrement
   elseif ch == '[' then
      local o          = term.cur[2]+((term.cur[1]-1)*term.offset+((term.sx-1)*term.offset))
      if term.ascii[o] > 0 then
         term.ascii[o] = term.ascii[o] - 1
         term.hex[o]   = term.hex[o] - 1
         term.draw     = true
      end
   elseif ch == 'S' then
      term.save = true
   end

end

module.input = input

return module
