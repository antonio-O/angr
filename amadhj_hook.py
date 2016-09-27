import angr
import logging

inp = angr.claripy.BVS('inp',32*8)

def main():
    logging.basicConfig()
    logging.getLogger('angr.path_group').setLevel(logging.DEBUG)
    p = angr.Project('amadhj',load_options={'auto_load_libs':False})
    chk = 0x4026d1
    read = 0x4026fd
    win = 0x40287f
    lose = map ((lambda x: x+chk), [0x7e,0x9c,0xba,0xd8,0xf6,0x114])
    
    state = p.factory.blank_state(addr = chk)
    p.hook(read,func=read_hook,length=5)
    pg = p.factory.path_group(state)
    ex = pg.explore(find=win,avoid=lose)
    for i in range(len(ex.found)):

        s = ex.found[i].state
        print i, s.se.any_str(inp)

def read_hook(state):
    print state.regs.rsi
    state.mem[state.regs.rsi:] = inp
main()
