import angr

def main():
    p = angr.Project('babyre',load_options={'auto_load_libs':False})
    win = 0x4028C7
    lose = 0x4028CE
    pass_len = 13
    main_addr = 0x40256B
    flag_addr = 0x4029F8
    scanf_offsets = (0x3e, 0x76, 0xae, 0xe6, 0x11e, 0x156, 0x18e, 0x1c6, 0x1fe, 0x236, 0x26e, 0x2a6, 0x2de)
    init_state = p.factory.blank_state(addr=main_addr)
    for offset in scanf_offsets:
        p.hook(main_addr+offset, func = scanf, length = 5)
    pg=p.factory.path_group(init_state)
    ex = pg.explore(find=win,avoid=lose)
    #print (ex)
    s = ex.found[0].state
    print s.posix.dumps(0),s.posix.dumps(1)
def scanf(state):
    #print (state.regs.rsi)
    state.mem[state.regs.rsi:] = state.se.BVS('c', 8)
main()
