@echo off

set /p pipe=Enter pipe name: 

:loop
echo Connecting to %pipe%
"c:\Program Files\Debugging Tools for Windows (x64)\windbg.exe" -y srv*https://msdl.microsoft.com/download/symbols -k com:pipe,port=\\.\pipe\%pipe%,resets=0,reconnect
goto loop
