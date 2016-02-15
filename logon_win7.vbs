' =================================================== '
'       Script de Logon dos Usuários Windows 7        '
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
dim LOGIN, DOMAIN, VNC_7, KAVAGENTE, DIROCS, OCSEXE, DIRBGINFO, BGINFOEXE, WINSYS, PUTTY, LSRUNAS, objShell, strCmd
dim objexec, oReg, objReg, strKeyPath, strStringValueName, strValue, strRegistryKey, strRegistryValue, binValue, dwValue, strValueName
dim FileClass, objFSO, usrProfile, PSSWD, INFO, COMMAND, colListOfServices, RUNPATH
set WshNetwork=CreateObject("Wscript.Network")
set WshShell=WScript.CreateObject("WScript.Shell")
WinDir=WshShell.ExpandEnvironmentStrings("%WinDir%")
ProgramFiles=WshShell.ExpandEnvironmentStrings("%ProgramFiles%")
SystemDrive=WshShell.ExpandEnvironmentStrings("%SystemDrive%")
strComputer = "."
LOGIN="ocs"
DOMAIN="SES"
PSSWD="MKcd61AL"
VNC_7=WinDir & "\UVNC"
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
      oReg.SetStringValue HKEY_CURRENT_USER,strRegistryKey,strRegistryValue,strValue
      'strRegistryValue = "ProxyEnabled"
      'dwValue = 1
      'oReg.SetStringValue HKEY_CURRENT_USER,strKeyPath,strStringValueName,strValue
  ' Página inicial do IE 
      LSRUNAS="\\arapiraca\ocs\windows\lsrunas.exe"
      INFO="/user:" & LOGIN & " " & "/password:" & PSSWD & " " & "/domain:" & DOMAIN & " " & "/command:"
      RUNPATH=" /n " & "/runpath:c:"
      COMMAND="""xcopy /Y \\arapiraca\ocs\utilnet\bat\startpage.bat" & " " & WinDir & """" 
      strCmd=(LSRUNAS & " " & INFO & COMMAND & " " & RUNPATH)
      objShell.Run strCmd, 0
      COMMAND="""xcopy /Y \\arapiraca\ocs\utilnet\files\prefs.js" & " " & WinDir & """"
      strCmd=(LSRUNAS & " " & INFO & COMMAND & " " & RUNPATH)
      objShell.Run strCmd, 0
      COMMAND="""xcopy /Y \\arapiraca\ocs\utilnet\files\firefox.vbs" & " " & WinDir & """"
      strCmd=(LSRUNAS & " " & INFO & COMMAND & " " & RUNPATH)
      objShell.Run strCmd, 0
      WScript.Sleep 2000
      'COMMAND="""regedit /S " & WinDir & "\startpage.reg"""
      'strCmd=(LSRUNAS & " " & INFO & COMMAND & " " & RUNPATH)
      'objShell.Run strCmd, 0
      'strKeyPath = "Software\Microsoft\Internet Explorer\Main"
      'strStringValueName = "Start Page"
      'strValue = "http://www.saude.al.gov.br"
      'oReg.SetStringValue HKEY_CURRENT_USER,strKeyPath,strStringValueName,strValue
      'set WshShell=CScript.CreateObject("WScript.Shell")
      'WshShell.RegWrite "HKCU\Software\Microsoft\Microsoft\Internet Explorer\Main\Start Page","http://www.saude.al.gov.br","REG_SZ"
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
      oReg.SetStringValue HKEY_CURRENT_USER,strKeyPath,strStringValueName,strValue
  ' Desabilitar UAC Windows 7
      strKeyPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Security Center"
      strValueName = "UACDisableNotify"
      dwValue = 1
      oReg.SetDWORDValue HKEY_LOCAL_MACHINE,strKeyPath,strValueName,dwValue
  ' Desabilitar firewall Windows 7
      strKeyPath = "SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"
      strValueName = "EnableFirewall"
      dwValue = 0
      oReg.SetDWORDValue HKEY_LOCAL_MACHINE,strKeyPath,strValueName,dwValue
  ' Desabilitar notificações na área de trabalho Windows 7
      strValueName = "DisableNotifications"
      dwValue = 1
      oReg.SetDWORDValue HKEY_LOCAL_MACHINE,strKeyPath,strValueName,dwValue
      strKeyPath = "\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
      strValueName = "EnableBalloonTips"
      dwValue = 0
      oReg.SetDWORDValue HKEY_CURRENT_USER,strKeyPath,strValueName,dwValue
  ' Reiniciando o serviço WSCSVC no Windows 7
      set objWMIService = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")
      set colListOfServices = objWMIService.ExecQuery ("Select * from Win32_Service Where Name ='wscsvc'")
      for each objService in colListOfServices
          objService.StopService()
          objService.StartService()
      next 
    
'Criando estrutura de diretórios 
set FileClass = CreateObject("Scripting.FileSystemObject")
if FileClass.FolderExists (DIROCS) = false then
   FileClass.CreateFolder (DIROCS)
end if
if FileClass.FolderExists (DIRBGINFO) = false then
   FileClass.CreateFolder (DIRBGINFO)
end if
if FileClass.FolderExists (VNC_7) = false then
   FileClass.CreateFolder (VNC_7)
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
strComputer = "."
strServiceName = "winvnc4" 
  function isServiceRunning(strComputer,strServiceName)
    strWMIQuery = "Select * from Win32_Service Where Name = '" & strServiceName & "' and state='Running'"
    set objWMIService = GETOBJECT("winmgmts:" & "{impersonationLevel=impersonate}!\\" & strComputer & "\root\cimv2")
    if objWMIService.ExecQuery(strWMIQuery).Count > 0 then
       isServiceRunning = true
    else
       isServiceRunning = false
    end if
  end function
  
  if isServiceRunning(strComputer,strServiceName) = true then
     set objWMIService = GetObject("winmgmts:" & "{impersonationLevel=impersonate}!\\" & strComputer & "\root\cimv2")
     set colServiceList = objWMIService.ExecQuery("Select * from Win32_Service where Name='" & strServiceName & "'")
     for each objService in colServiceList
         objService.StopService()
     next
  end if
    
  if objFSO.FileExists (VNC_7 & "\check_install.exe") = false then
     objFSO.CopyFile "\\arapiraca\ocs\utilnet\vnc_win7\my.inf",VNC_7 & "\",OverwriteExisting
     objFSO.CopyFile "\\arapiraca\ocs\utilnet\vnc_win7\ultravnc.exe",VNC_7 & "\",OverwriteExisting
     WScript.Sleep 10000
     ' Iniciando a instalação do VNC
         strComputer = "."
         set objWMIService=GetObject("winmgmts:\\" & strComputer & "\root\CIMV2")
         set objShell=CreateObject("WScript.shell")
         INFO="/user:" & LOGIN & " " & "/password:" & PSSWD & " " & "/domain:" & DOMAIN & " " & "/command:"
         COMMAND="""" & VNC_7 & "\ultravnc.exe " & "/silent /LOADINF=""" & VNC_7 & "\my.inf"""""
	     RUNPATH="/n /runpath:c:"
         strCmd=(LSRUNAS & " " & INFO & COMMAND & " " & RUNPATH)
         objShell.Run strCmd, 0
         WScript.Sleep 20000
         objFSO.CopyFile "\\arapiraca\ocs\utilnet\vnc_win7\ultravnc.ini",VNC_7 & "\",OverwriteExisting
         objFSO.CopyFile "\\arapiraca\ocs\utilnet\vnc_win7\winvnc.exe",VNC_7 & "\",OverwriteExisting
         objFSO.CopyFile "\\arapiraca\ocs\utilnet\vnc_win7\uvnc_settings.exe",VNC_7 & "\",OverwriteExisting
         WScript.Sleep 5000
    ' Diretivas para UltraVNC
         COMMAND="""netsh advfirewall firewall add rule name=UltraVNC dir=in program=" & VNC_7 &"\winvnc.exe action=allow"""
	     RUNPATH="/n /runpath:c:"
         strCmd=(LSRUNAS & " " & INFO & COMMAND & " " & RUNPATH)
         objShell.Run strCmd, 0
         COMMAND="""netsh advfirewall firewall add rule name=" & """UltraVNC Main""" & " " & "protocol=TCP dir=in localport=5900 action=allow"""
	     RUNPATH="/n /runpath:c:"
         strCmd=(LSRUNAS & " " & INFO & COMMAND & " " & RUNPATH)
         objShell.Run strCmd, 0
         COMMAND="""netsh advfirewall firewall add rule name=" & """UltraVNC HTTP""" & " " & "protocol=TCP dir=in localport=5800 action=allow"""
	     RUNPATH="/n /runpath:c:"
         strCmd=(LSRUNAS & " " & INFO & COMMAND & " " & RUNPATH)
         objShell.Run strCmd, 0
         COMMAND="""netsh advfirewall set allprofiles state off"""
	     RUNPATH="/n /runpath:c:"
         strCmd=(LSRUNAS & " " & INFO & COMMAND & " " & RUNPATH)
         objShell.Run strCmd, 0
         set objWMIService = GetObject("winmgmts:" & "{impersonationLevel=impersonate}!\\" & strComputer & "\root\cimv2")
         set colServiceList = objWMIService.ExecQuery("Select * from Win32_Service where Name='" & strServiceName & "'")
         strServiceName = "MpsSvc"
         for each objService in colServiceList
             objService.StopService()
         next
    ' Verificar processo do UltraVNC
         strComputer = "."
         strServiceName = "uvnc_service" 
		 function isServiceRunning(strComputer,strServiceName)
			strWMIQuery = "Select * from Win32_Service Where Name = '" & strServiceName & "' and state='Running'"
			set objWMIService = GETOBJECT("winmgmts:" & "{impersonationLevel=impersonate}!\\" & strComputer & "\root\cimv2")
			if objWMIService.ExecQuery(strWMIQuery).Count > 0 then
				isServiceRunning = true
			else
				isServiceRunning = false
			end if
       		end function
         	if isServiceRunning(strComputer,strServiceName) = false then
			set colServiceList = objWMIService.ExecQuery ("Select * from Win32_Service where Name='" & strServiceName & "'")
			for each objService in colServiceList
               			objService.StartService()
            		next
		end if
       
  else
    strComputer = "."
    strServiceName = "uvnc_service" 
	function isServiceRunning(strComputer,strServiceName)
       		strWMIQuery = "Select * from Win32_Service Where Name = '" & strServiceName & "' and state='Running'"
       		set objWMIService = GETOBJECT("winmgmts:" & "{impersonationLevel=impersonate}!\\" & strComputer & "\root\cimv2")
       		if objWMIService.ExecQuery(strWMIQuery).Count > 0 then
          		isServiceRunning = true
       		else
          		isServiceRunning = false
       		end if
    	end function
    if isServiceRunning(strComputer,strServiceName) = false then
       set colServiceList = objWMIService.ExecQuery ("Select * from Win32_Service where Name='" & strServiceName & "'")
       for each objService in colServiceList
           objService.StopService()
           objService.StartService()
       next
    end if
    
  end if

Wscript.Quit 
