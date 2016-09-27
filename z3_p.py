import angr
import simuvex

import claripy
proj = angr.Project('./z4',load_options={'auto_load_libs':False})

main=0x400c43

arg1 = claripy.BVS('arg1',8*16)



initial_state = proj.factory.entry_state(args=["./z3_patched",arg1])

pg = proj.factory.path_group(initial_state)


pg.explore(find=0x400d01,avoid=[0x400d08,0x400d12])

found = pg.found[0]


print "[%s]\n"%found
print found.state.se.any_str(found.state.memory.load(found.state.regs.rbp,200))
