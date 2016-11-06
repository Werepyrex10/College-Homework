build: so_scheduler.obj my_heap.obj
	link /nologo /dll /out:libscheduler.dll /implib:libscheduler.lib so_scheduler.obj my_heap.obj

so_scheduler.obj: so_scheduler.c so_scheduler.h
	cl /c /W3 so_scheduler.c

my_heap.obj: my_heap.c my_heap.h
	cl /c /W3 my_heap.c

clean:
	del *.obj libvmsim.*