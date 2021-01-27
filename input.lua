local util = require "util"
local drw  = require "drw"
-- input function
-- 1. send ansi command for move command
-- 2. check if within bounds
-- 3. draw status bar
local module = {}

local function input(term)

   local c = util.get_char()
   local ch = util.last_char(c())

   if ch == 'q' then 
      term.running = false
   elseif ch == 'j' then
      if (term.cur[1] <= term.size[1]-3) then  
         term.cur_d(1)
         term.cur[1] = term.cur[1] < term.size[1] and term.cur[1]+1 or term.cur[1]
      end
   elseif ch == 'k' then 
      if term.cur[1] > 1 then
         term.cur_u(1)
         term.cur[1] = term.cur[1] > 1 and term.cur[1]-1 or term.cur[1]
      end
   elseif ch == 'h' then 
      if term.cur[2] > 1 then 
         term.cur_l(1) 
         term.cur[2] = term.cur[2] >-  1 and term.cur[2]-1 or term.cur[2]
      end
   elseif ch == 'l' then 
      if term.cur[2] < term.offset then
         term.cur_r(1) 
         term.cur[2] = term.cur[2]+1
      end
   elseif ch == 'n' then
      if term.sx-2 > (#term.buffer/0x10)-term.size[1] then return end
      term.sx = term.sx + 1
      term.draw = true
   elseif ch == 'p' then
      if term.sx <= 1 then return end
      term.sx = term.sx - 1
      term.draw = true
   elseif ch == 'g' then -- resetting cursor to original position
      term:cur_reset()
      term.cur[1], term.cur[2] = 1, 1
      term.sx = 1
      drw.draw_status_bar(term, offset)
      term.cur_r(12+(term.offset*2)) 
      term.cur_d(1)
      term.draw = true
   elseif ch == 'G' then
      return
   end
end

module.input= input

return module
