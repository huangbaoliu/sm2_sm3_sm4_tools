import  os
if __name__ == '__main__':
    from PyInstaller.__main__ import run
    opts=['sm_tools_dist.py','-w','-F', '--version-file', 'file_version.txt']
    run(opts)