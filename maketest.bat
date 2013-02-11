@echo off

rem Set APRINC to your APR include directory
rem Set APRLIB to your APR library directory

set APRINC=c:\apr\include
set APRLIB=c:\apr\lib

set LIB=%APRLIB%;%LIB%

cl /nologo /c /I %APRINC% /D WIN32 test_hash.c
link /libpath:%APRLIB% /subsystem:console /incremental:no /out:test_hash.exe test_hash.obj libapr-1.lib libaprutil-1.lib kernel32.lib user32.lib

@echo on
