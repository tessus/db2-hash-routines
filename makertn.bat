@echo off

rem Set the DB2PATH variable to your DB2 base path, e.g., c:\sqllib
rem Set APRINC to your APR include directory
rem Set APRLIB to your APR library directory

set DB2PATH=c:\Program Files\IBM\sqllib
set APRINC=c:\apr\include
set APRLIB=c:\apr\lib

cl -Od /nologo /c /I %APRINC% /D WIN32 db2hash.c hash.c
link /libpath:%APRLIB% /subsystem:console /incremental:no /out:hash.dll /dll /def:hash.def db2hash.obj hash.obj libapr-1.lib libaprutil-1.lib db2api.lib kernel32.lib user32.lib

copy hash.dll "%DB2PATH%\function"

@echo on
