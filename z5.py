import angr

argv1 = angr.claripy.BVS('argv1',8*16)

def main():
    p = angr.Project('z4',load_options={'auto_load_libs':False})
    win = 0x400d01
    lose = 0x400d08
    init_state = p.factory.entry_state(args=['z4',argv1])
    p.hook(0x400ce0,func=printf,length=5)
    p.hook(0x400c8c,func=strcpy,length=5)
    pg=p.factory.path_group(init_state)
    pg.explore(find=win,avoid=lose)
    found = pg.found[0]
    print found.state.se.any_str(argv1)

def printf(state):
    pass

def strcpy(state):
    print state.regs.rsi
    state.mem[state.regs.rdi:] = argv1
main()
