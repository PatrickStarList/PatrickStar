@echo off

REM $Id$

REM -- --------------------------------------------------------------
REM -- If you are having problems running "NMAKE", you probably
REM -- haven't configured the proper paths.  Uncomment the following
REM -- line to help configure this properly.  You will need to update
REM -- the line to reflect whichever drive/path you specified when
REM -- installing Visual C++ 6.0.
REM -- --------------------------------------------------------------
REM call "C:\Program Files\Microsoft Visual Studio\VC98\Bin\vcvars32.bat"


DEL PatrickStar___Win32_MySQL_Release\PatrickStar.exe
DEL PatrickStar___Win32_SQLServer_Release\PatrickStar.exe
DEL PatrickStar___Win32_Oracle_Release\PatrickStar.exe


NMAKE /f "PatrickStar.mak" CFG="PatrickStar - Win32 MySQL Release"

NMAKE /f "PatrickStar.mak" CFG="PatrickStar - Win32 SQLServer Release"

NMAKE /f "PatrickStar.mak" CFG="PatrickStar - Win32 Oracle Release"
