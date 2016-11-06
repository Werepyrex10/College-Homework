build: common_win.obj vmsim.obj
	link /nologo /dll /out:libvmsim.dll /implib:libvmsim.lib common_win.obj vmsim.obj

common_win.obj: common_win.c
	cl /c common_win.c

vmsim.obj: vmsim.c
	cl /c vmsim.c

clean:
	del *.obj libvmsim.*