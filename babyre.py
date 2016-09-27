import angr
def main():
    proj = angr.Project('./babyre',  load_options={'auto_load_libs': False})
    path_group = proj.factory.path_group(threads=4)

    path_group.explore(find = 0x4028C7, avoid = 0x4028c9)
    
    print path_group.found[0].state.posix.dumps(0)
    print path_group.found[0].state.posix.dumps(1)
main()
