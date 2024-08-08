@echo off

nasm -f bin stage2.x64.asm -o stage2.x64.bin
python ../maldev_tools/transform/transform_file.py -i stage2.x64.bin -o stage2.x64.bin.asm -vn stage2_x64

nasm -f bin stage1.x64.asm -o stage1.x64.bin
python ../maldev_tools/transform/transform_file.py -i stage1.x64.bin -o stage1.x64.bin.h -vn stage1_x64

cl /nologo /W3 /MT /O2 /GS- /DNDEBUG base.c /link /entry:main kernel32.lib vcruntime.lib /out:base.exe

del *.obj