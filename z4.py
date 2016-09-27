import angr

def main():
    p = angr.Project('z4',load_options={'auto_load_libs':False})
    win = 0x400d01
    lose = 0x400d08
    argv1 = angr.claripy.BVS('argv1',8*16)
    init_state = p.factory.entry_state(args=['z4',argv1])
    p.hook(0x400ce0,func=printf,length=5)
    pg=p.factory.path_group(init_state)
    pg.explore(find=win,avoid=lose)
    found = pg.found[0]
    print found.state.se.any_str(argv1)

def printf(state):
    pass

main()
