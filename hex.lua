-- Imports
local ter  = require "terminal"
local util = require "util"
local drw  = require "drw"
local input = require "input"

-- All colors in decimal
COLORS = {
   MAGENTA = 128,
   RED = 124,
   BLACK = 0,
   WHITE = 255,
   BLUE = 12,
   LIGHTBLUE = 14,
}

--   local opts = util.getopt(arg, "o") 
--   local buf = util.r_file(arg[1] or nil)
-- main loop
function loop()
   -- getting the flags
   local offset = 16
   -- read file
   -- init term
  ter:init_term(offset)
  -- read file
  drw.draw_ui(ter)
  drw.draw_status_bar(ter)
  local ch
  -- main loop
  while ter.running do
     input.input(ter)
     if ter.draw then 
        drw.draw_ui(ter)
        ter.draw=false 
     end
     drw.draw_status_bar(ter)
  end
  ter:free_term()
end


loop()
