@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcmapviewinjection.cpp /link /OUT:mapviewinjection.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
del *.obj