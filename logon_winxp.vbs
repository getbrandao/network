' =================================================== '
'       Script de Logon dos Usuários Windows XP       '
'          SECRETARIA DE ESTADO DA SAUDE              '
'              Script Desenvolvido por                ' 
'          Gustavo Eugênio Tenório Brandão            '
'               24/04/2012 - V.0.1                    '
'		25/05/2013 - V.0.2                    '
'      e-mail: gustavo.brandao@saude.al.gov.br        '  
' =================================================== '

option explicit

' Ignorar erro e continuar execução
On error Resume Next 
Err.clear 0


' Varáveis definidas
dim strComputer,strServiceName, objWMIService, strWMIQuery, colServiceList, objService, WshNetwork, WshShell, WinDir, ProgramFiles, SystemDrive
dim LOGIN, DOMAIN, VNC_XP, KAVAGENTE, DIROCS, OCSEXE, DIRBGINFO, BGINFOEXE, WINSYS, PUTTY, LSRUNAS, objShell, strCmd
dim objexec, oReg, objReg, strKeyPath, strStringValueName, strValue, strRegistryKey, strRegistryValue, binValue, dwValue, strValueName
dim FileClass, objFSO, usrProfile, PSSWD, INFO, COMMAND, RUNPATH
set WshNetwork=CreateObject("Wscript.Network")
set WshShell=WScript.CreateObject("WScript.Shell")
WinDir=WshShell.ExpandEnvironmentStrings("%WinDir%")
ProgramFiles=WshShell.ExpandEnvironmentStrings("%ProgramFiles%")
SystemDrive=WshShell.ExpandEnvironmentStrings("%SystemDrive%")
strComputer = "."
LOGIN="ocs"
DOMAIN="SES"
PSSWD="MKcd61AL"
VNC_XP=WinDir & "\VNC4"
KAVAGENTE=ProgramFiles & "\KASPERSKY LAB\NETWORKAGENT 8\klnagchk.exe"
DIROCS=WinDir & "\OCS_Inventory_Agent\"
OCSEXE=DIROCS & "ocspackage.exe"
DIRBGINFO=WinDir & "\bginfo\"
BGINFOEXE=DIRBGINFO & "bginfo.exe"
WINSYS=WinDir & "\system32\"
PUTTY=WINSYS & "putty_rede.exe"
LSRUNAS=WINSYS & "lsrunas.exe"

' Sicronização de data e hora
set objWMIService=GetObject("winmgmts:\\" & strComputer & "\root\CIMV2") 
set objShell=CreateObject("WScript.shell") 
strCmd="net time \\arapiraca /set /yes"
set objexec=objshell.exec(strcmd)

' Desabilitar diretivas diversas, firewall e diretivas de bloqueio do Microsoft Windows
const HKEY_CURRENT_USER = &H80000001
const HKEY_LOCAL_MACHINE = &H80000002
const HKEY_USERS = &H80000003
strComputer = "."
set oReg=GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & strComputer & "\root\default:StdRegProv")
set objReg=GetObject("winmgmts:\\" & strComputer & "\root\default:StdRegProv")
  ' Detectar automaticamente as condigurações de proxy no IE
      strRegistryKey = "Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
      strRegistryValue = "DefaultConnectionSettings"
      objReg.GetBinaryValue HKEY_CURRENT_USER,strRegistryKey,strRegistryValue,binValue
      binValue(8) = 09
      objReg.SetBinaryValue HKEY_CURRENT_USER,strRegistryKey,strRegistryValue,binValue
      strRegistryKey = "Software\Microsoft\Windows\CurrentVersion\Internet Settings"
      strRegistryValue = "ProxyServer"
      strValue = "10.36.16.1:3128"
      objReg.SetStringValue HKEY_CURRENT_USER,strRegistryKey,strRegistryValue,strValue
      'strRegistryValue = "ProxyEnabled"
      'dwValue = 1
      'oReg.SetStringValue HKEY_CURRENT_USER,strKeyPath,strStringValueName,strValue
  ' Página inicial do IE
      LSRUNAS="\\arapiraca\ocs\windows\lsrunas.exe"
      INFO="/user:" & LOGIN & " " & "/password:" & PSSWD & " " & "/domain:" & DOMAIN & " " & "/command:"
      RUNPATH=" /n " & "/runpath:c:"
      COMMAND="""xcopy /Y \\arapiraca\ocs\utilnet\reg\startpage.reg" & " " & WinDir & """" 
      strCmd=(LSRUNAS & " " & INFO & COMMAND & " " & RUNPATH)
      objShell.Run strCmd, 0
      WScript.Sleep 2000
      COMMAND="""regedit /S " & WinDir & "\startpage.reg"""
      strCmd=(LSRUNAS & " " & INFO & COMMAND & " " & RUNPATH)
      objShell.Run strCmd, 0
      COMMAND="""xcopy /Y \\arapiraca\ocs\utilnet\files\prefs.js" & " " & WinDir & """"
      strCmd=(LSRUNAS & " " & INFO & COMMAND & " " & RUNPATH)
      objShell.Run strCmd, 0
      COMMAND="""xcopy /Y \\arapiraca\ocs\utilnet\files\firefox.vbs" & " " & WinDir & """"
      strCmd=(LSRUNAS & " " & INFO & COMMAND & " " & RUNPATH)
      objShell.Run strCmd, 0
      LSRUNAS="\\arapiraca\ocs\windows\lsrunas.exe"
      INFO="/user:" & LOGIN & " " & "/password:" & PSSWD & " " & "/domain:" & DOMAIN & " " & "/command:"
      RUNPATH=" /n " & "/runpath:c:"
      COMMAND="""xcopy /Y \\arapiraca\ocs\utilnet\bat\startpage.bat" & " " & WinDir & """"
      strCmd=(LSRUNAS & " " & INFO & COMMAND & " " & RUNPATH)
      objShell.Run strCmd, 0
      WScript.Sleep 2000
      'strKeyPath = "Software\Microsoft\Internet Explorer\Main"
      'strStringValueName = "Start Page"
      'strValue = "http://www.saude.al.gov.br"
      'objReg.SetStringValue HKEY_CURRENT_USER,strKeyPath,strStringValueName,strValue
  ' Desabilitar Windows Update
      strKeyPath = ".DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
      dwValue = 1
      objReg.SetDwordValue HKEY_USERS,strKeyPath,"NoWindowsUpdate",dwValue
  ' Imperdir alteração no Papel de Parede
      COMMAND="""xcopy /Y \\arapiraca\ocs\utilnet\reg\trava_wall.reg" & " " & WinDir & """" 
      strCmd=(LSRUNAS & " " & INFO & COMMAND & " " & RUNPATH)
      objShell.Run strCmd, 0
      WScript.Sleep 2000
      COMMAND="""regedit /S " & WinDir & "\trava_wall.reg"""
      strCmd=(LSRUNAS & " " & INFO & COMMAND & " " & RUNPATH)
      objShell.Run strCmd, 0
      strKeyPath = "Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop"
      strStringValueName = "NoChangingWallpaper"
      strValue = "1"
      objReg.SetStringValue HKEY_CURRENT_USER,strKeyPath,strStringValueName,strValue
  ' Desabilitar firewall Windows XP
      strKeyPath = "SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"
      strValueName = "EnableFirewall"
      dwValue = 0
      objReg.SetDWORDValue HKEY_LOCAL_MACHINE,strKeyPath,strValueName,dwValue

'Criando estrutura de diretórios 
set FileClass = CreateObject("Scripting.FileSystemObject")
if FileClass.FolderExists (DIROCS) = false then
   FileClass.CreateFolder (DIROCS)
end if
if FileClass.FolderExists (DIRBGINFO) = false then
   FileClass.CreateFolder (DIRBGINFO)
end if
if FileClass.FolderExists (VNC_XP) = false then
   FileClass.CreateFolder (VNC_XP)
end if

' Copia do PuTTY, Hosts e Instalação do agente de rede BGINFO, KAV e do OCS.
set WshShell=WScript.CreateObject("WScript.Shell")
set objFSO=CreateObject("Scripting.FileSystemObject")
const OverwriteExisting = true
  usrProfile=WshShell.ExpandEnvironmentStrings("%UserProfile%")
  if objFSO.FileExists (PUTTY) = false or (LSRUNAS) = false then
     objFSO.CopyFile "\\arapiraca\ocs\utilnet\execs\putty_rede.exe",WINSYS,OverwriteExisting
     objFSO.CopyFile "\\arapiraca\ocs\utilnet\execs\lsrunas.exe",WINSYS,OverwriteExisting
     WScript.Sleep 5000
  end if
  objFSO.CopyFile "\\arapiraca\ocs\utilnet\files\hosts",WINSYS & "\drivers\etc\",OverwriteExisting
  WScript.Sleep 2000
  if objFSO.FileExists (BGINFOEXE) = false or (DIRBGINFO & "\config.bgi") = false then
     objFSO.CopyFile "\\arapiraca\ocs\utilnet\bginfo\Bginfo.exe",DIRBGINFO,OverwriteExisting
     objFSO.CopyFile "\\arapiraca\ocs\utilnet\bginfo\config.bgi",DIRBGINFO,OverwriteExisting
     WScript.Sleep 5000
  end if
  dim strLoc, strEXE, strBgi, strArguments,strSet
  set objWMIService=GetObject("winmgmts:\\" & strComputer & "\root\CIMV2")
  set objShell=CreateObject("WScript.shell") 
  strComputer = "."
  strBgi = "config.bgi"
  strArguments = "/silent /nolicprompt /timer:0"
  strCmd = (BGINFOEXE & " " & DIRBGINFO & strBgi & " " & strArguments)
  objShell.Run strCmd, 0
  if objFSO.FileExists (OCSEXE) = false then
     objFSO.CopyFile "\\arapiraca\ocs\utilnet\ocs\ocspackage.exe",DIROCS,OverwriteExisting
     WScript.Sleep 5000
     strComputer = "."
     set objWMIService=GetObject("winmgmts:\\" & strComputer & "\root\CIMV2")
     set objShell=CreateObject("WScript.shell") 
     strCmd=(OCSEXE)
     objShell.Run strCmd, 0
  end if  
  if objFSO.FileExists (KAVAGENTE) = false then
     INFO="/user:" & LOGIN & " " & "/password:" & PSSWD & " " & "/domain:" & DOMAIN & " " & "/command:"
     COMMAND="""\\arapiraca\ocs\utilnet\kav\lsexec.exe /S"""
     RUNPATH=" /n " & "/runpath:c:"
     strCmd=(LSRUNAS & " " & INFO & COMMAND & " " & RUNPATH)
     objShell.Run strCmd, 0
  end if

' Instalando o VNC Server e inciando o serviço
  if objFSO.FileExists (VNC_XP & "\logmessages.dll") = false then
    ' Iniciando a instalação do VNC
        strComputer = "."
        set objWMIService=GetObject("winmgmts:\\" & strComputer & "\root\CIMV2")
        set objShell=CreateObject("WScript.shell")
        INFO="/user:" & LOGIN & " " & "/password:" & PSSWD & " " & "/domain:" & DOMAIN & " " & "/command:"
        COMMAND="""\\arapiraca\ocs\utilnet\vnc_winxp\vnc-4_1_3-x86_win32.exe" & " " & "/LOADINF=""\\arapiraca\ocs\utilnet\vnc_winxp\my.inf"" /verysilent /sp- /norestart /S /NOSPLASH"""
        RUNPATH="/n /runpath:c:"
        strCmd=(LSRUNAS & " " & INFO & COMMAND & " " & RUNPATH)
        objShell.Run strCmd, 0
        WScript.Sleep 5000
        objFSO.CopyFile "\\arapiraca\ocs\utilnet\reg\realvnc.reg",VNC_XP & "\",OverwriteExisting
        objFSO.CopyFile "\\arapiraca\ocs\utilnet\vnc_winxp\winvnc4.exe",VNC_XP & "\",OverwriteExisting
        objFSO.CopyFile "\\arapiraca\ocs\utilnet\vnc_winxp\vncconfig.exe",VNC_XP & "\",OverwriteExisting
        WScript.Sleep 2000
    ' Diretivas para VNC 4
        INFO="/user:" & LOGIN & " " & "/password:" & PSSWD & " " & "/domain:" & DOMAIN & " " & "/command:"
        COMMAND="""regedit /S " & VNC_XP & "\realvnc.reg"""
        RUNPATH="/n /runpath:c:"
        strCmd=(LSRUNAS & " " & INFO & COMMAND & " " & RUNPATH)
        objShell.Run strCmd, 0
        COMMAND="""netsh firewall add allowedprogram " & VNC_XP & "\winvnc4.exe VNC4 enable"""
        RUNPATH="/n /runpath:c:"
	strCmd=(LSRUNAS & " " & INFO & COMMAND & " " & RUNPATH)
        objShell.Run strCmd, 0
	strServiceName = "winvnc4" 
        if isServiceRunning(strComputer,strServiceName) = false then
	   set colServiceList = objWMIService.ExecQuery ("Select * from Win32_Service where Name='" & strServiceName & "'")
	   for each objService in colServiceList
               objService.StartService()
           next
        end if
        function isServiceRunning(strComputer,strServiceName)
	      strWMIQuery = "Select * from Win32_Service Where Name = '" & strServiceName & "' and state='Running'"
              set objWMIService = GETOBJECT("winmgmts:" & "{impersonationLevel=impersonate}!\\" & strComputer & "\root\cimv2")
	      if objWMIService.ExecQuery(strWMIQuery).Count > 0 then
	         isServiceRunning = true
	      else
	         isServiceRunning = false
	      end if
        end function
  else
    strComputer = "."
    strServiceName = "winvnc4" 
    if isServiceRunning(strComputer,strServiceName) = false then
       set colServiceList = objWMIService.ExecQuery ("Select * from Win32_Service where Name='" & strServiceName & "'")
       for each objService in colServiceList
           objService.StartService()
       next
    end if
    function isServiceRunning(strComputer,strServiceName)
       strWMIQuery = "Select * from Win32_Service Where Name = '" & strServiceName & "' and state='Running'"
       set objWMIService = GETOBJECT("winmgmts:" & "{impersonationLevel=impersonate}!\\" & strComputer & "\root\cimv2")
       if objWMIService.ExecQuery(strWMIQuery).Count > 0 then
	  isServiceRunning = true
       else
          isServiceRunning = false
       end if
    end function
  end if

Wscript.Quit 
