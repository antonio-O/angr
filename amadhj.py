import angr

main_addr = 0x40298f 
win = 0x40288d
p = angr.Project('amadhj',load_options={'auto_load_libs':False})

state = p.factory.blank_state(addr = main_addr)

pg = p.factory.path_group(state)
ex = pg.explore(find=win)
s = ex.found[0].state
print s.posix.dumps(0), s.posix.dumps(1)
