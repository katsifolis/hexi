### What are you making?
A hex editor.

* No deps  
* C99

---

### Why do you need a hex editor
* Game & File hacking: *by changing values regarding health, currency, stats etc*
* Quick File patching
* File-Data Carving or data recovery in general

---
### Proposal

* Binary templating: *Given a simple descriptive config file, highlight the information*
	* [Katai struct](https://kaitai.io): *parser for binary structures*  

* Inline disassembly: *using objdump or llvm*
	* [capstone](https://capstone-engine.org): *dissasembly framework*  

### Papers
* [Digging for data structures](https://ben.ransford.org/srg/papers/cozzie--digging.pdf) 
* [MemPick: High-Level Data Structure Detection in C/C++ Binaries](https://www.cs.vu.nl/~herbertb/papers/mempick_wcre13.pdf)
* [Howard: a dynamic excavator for reverse engineering data structures](http://www.syssec-project.eu/m/page-media/3/howard-ndss11.pdf)
* [Tupni: Automatic Reverse Engineering of Input Formats](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/tupni-ccs08.pdf)
* [A method for preventing online games hacking using memory monitoring](https://onlinelibrary.wiley.com/doi/epdf/10.4218/etrij.2019-0427)
* [Game traffic analysis: an MMORPG perspective](https://www.researchgate.net/publication/220937663_Game_traffic_analysis_an_MMORPG_perspective)
