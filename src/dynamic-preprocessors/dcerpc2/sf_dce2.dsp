# Microsoft Developer Studio Project File - Name="sf_dce2" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=sf_dce2 - Win32 IPv6 Release
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "sf_dce2.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "sf_dce2.mak" CFG="sf_dce2 - Win32 IPv6 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "sf_dce2 - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "sf_dce2 - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "sf_dce2 - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 2
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "SF_SMTP_EXPORTS" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I ".\includes" /I "..\libs" /I "..\include" /I "..\..\win32\Win32-Includes" /I ".\\" /I "..\..\win32\Win32-Includes\WinPCAP" /I "..\..\..\daq\api" /I "..\..\..\daq\sfbpf" /D "NDEBUG" /D "ENABLE_PAF" /D "SF_SNORT_PREPROC_DLL" /D "_WINDOWS" /D "_USRDLL" /D "ACTIVE_RESPONSE" /D "GRE" /D "MPLS" /D "TARGET_BASED" /D "PERF_PROFILING" /D "ENABLE_RESPOND" /D "ENABLE_REACT" /D "_WINDLL" /D "WIN32" /D "_MBCS" /D "HAVE_CONFIG_H" /D "_AFXDLL" /D SIGNAL_SNORT_READ_ATTR_TBL=30 /FR /FD /c
# SUBTRACT CPP /X /YX
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG" /d "_AFXDLL"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 ws2_32.lib /nologo /dll /machine:I386

!ELSEIF  "$(CFG)" == "sf_dce2 - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 2
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "SF_SMTP_EXPORTS" /YX /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /ZI /Od /I ".\includes" /I "..\libs" /I "..\include" /I "..\..\win32\Win32-Includes" /I ".\\" /I "..\..\win32\Win32-Includes\WinPCAP" /I "..\..\..\daq\api" /I "..\..\..\daq\sfbpf" /D "_DEBUG" /D "DEBUG" /D "ENABLE_PAF" /D "SF_SNORT_PREPROC_DLL" /D "_WINDOWS" /D "_USRDLL" /D "ACTIVE_RESPONSE" /D "GRE" /D "MPLS" /D "TARGET_BASED" /D "PERF_PROFILING" /D "ENABLE_RESPOND" /D "ENABLE_REACT" /D "_WINDLL" /D "WIN32" /D "_MBCS" /D "HAVE_CONFIG_H" /D "_AFXDLL" /D SIGNAL_SNORT_READ_ATTR_TBL=30 /FR /FD /GZ /c
# SUBTRACT CPP /X /YX
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG" /d "_AFXDLL"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 ws2_32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept

!ENDIF 

# Begin Target

# Name "sf_dce2 - Win32 Release"
# Name "sf_dce2 - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\dce2_cl.c
# End Source File
# Begin Source File

SOURCE=.\dce2_co.c
# End Source File
# Begin Source File

SOURCE=.\dce2_config.c
# End Source File
# Begin Source File

SOURCE=.\dce2_debug.c
# End Source File
# Begin Source File

SOURCE=.\dce2_event.c
# End Source File
# Begin Source File

SOURCE=.\dce2_http.c
# End Source File
# Begin Source File

SOURCE=.\dce2_list.c
# End Source File
# Begin Source File

SOURCE=.\dce2_memory.c
# End Source File
# Begin Source File

SOURCE=.\dce2_paf.c
# End Source File
# Begin Source File

SOURCE=.\dce2_roptions.c
# End Source File
# Begin Source File

SOURCE=.\dce2_smb.c
# End Source File
# Begin Source File

SOURCE=.\dce2_smb2.c
# End Source File
# Begin Source File

SOURCE=.\dce2_stats.c
# End Source File
# Begin Source File

SOURCE=.\dce2_tcp.c
# End Source File
# Begin Source File

SOURCE=.\dce2_udp.c
# End Source File
# Begin Source File

SOURCE=.\dce2_utils.c
# End Source File
# Begin Source File

SOURCE="..\..\win32\WIN32-Code\inet_aton.c"
# End Source File
# Begin Source File

SOURCE="..\..\win32\WIN32-Code\inet_pton.c"
# End Source File
# Begin Source File

SOURCE=..\include\sf_dynamic_preproc_lib.c
# End Source File
# Begin Source File

SOURCE=..\include\sf_ip.c
# End Source File
# Begin Source File

SOURCE=..\include\sfPolicyUserData.c
# End Source File
# Begin Source File

SOURCE=..\include\sfrt.c
# End Source File
# Begin Source File

SOURCE=..\include\sfrt_dir.c
# End Source File
# Begin Source File

SOURCE=.\PatrickStar_dce2.c
# End Source File
# Begin Source File

SOURCE=.\spp_dce2.c
# End Source File
# Begin Source File

SOURCE="..\..\win32\WIN32-Code\strtok_r.c"
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\dce2_cl.h
# End Source File
# Begin Source File

SOURCE=.\dce2_co.h
# End Source File
# Begin Source File

SOURCE=.\dce2_config.h
# End Source File
# Begin Source File

SOURCE=.\dce2_debug.h
# End Source File
# Begin Source File

SOURCE=.\dce2_event.h
# End Source File
# Begin Source File

SOURCE=.\dce2_http.h
# End Source File
# Begin Source File

SOURCE=.\dce2_list.h
# End Source File
# Begin Source File

SOURCE=.\dce2_memory.h
# End Source File
# Begin Source File

SOURCE=.\dce2_paf.h
# End Source File
# Begin Source File

SOURCE=.\dce2_roptions.h
# End Source File
# Begin Source File

SOURCE=.\dce2_session.h
# End Source File
# Begin Source File

SOURCE=.\dce2_smb.h
# End Source File
# Begin Source File

SOURCE=.\dce2_smb2.h
# End Source File
# Begin Source File

SOURCE=.\dce2_stats.h
# End Source File
# Begin Source File

SOURCE=.\dce2_tcp.h
# End Source File
# Begin Source File

SOURCE=.\dce2_udp.h
# End Source File
# Begin Source File

SOURCE=.\dce2_utils.h
# End Source File
# Begin Source File

SOURCE=.\sf_preproc_info.h
# End Source File
# Begin Source File

SOURCE=.\PatrickStar_dce2.h
# End Source File
# Begin Source File

SOURCE=.\spp_dce2.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# End Target
# End Project
