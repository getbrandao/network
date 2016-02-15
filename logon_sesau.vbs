' =================================================== '
'       Script de Logon dos Usuários da SESAU         '
'          SECRETARIA DE ESTADO DA SAUDE              '
'              Script Desenvolvido por                ' 
'          Gustavo Eugênio Tenório Brandão            '
'               24/04/2012 - V.0.1                    '
'		25/05/2013 - V.0.2                    '
'      e-mail: gustavo.brandao@saude.al.gov.br        '  
' =================================================== '

' Ignorar erro e continuar execução
On error Resume Next 
Err.clear 0

' Variáveis Definidas.
dim objWMIService, objShell, strCmd, WshShell, LOGIN, PSSWD, BGINFOEXE, strComputer
dim strBgi, strArguments, INFO, COMMAND, RUNPATH, DOMAIN, DIRBGINFO, WinDir, SystemRoot
dim objNetwork, strDomain, strUser, objUser, objGroup, strGroupMemberships, NUM, SETOR
strComputer = "."
set objWMIService=GetObject("winmgmts:\\" & strComputer & "\root\CIMV2")
set objShell=CreateObject("WScript.shell")
set WshShell=WScript.CreateObject("WScript.Shell")
WinDir=WshShell.ExpandEnvironmentStrings("%WinDir%")
SystemRoot=WshShell.ExpandEnvironmentStrings("%SystemRoot%")
LOGIN="ocs"
DOMAIN="SES"
PSSWD="MKcd61AL"

'  Execução dos Scripts de acordo com a versão Microsoft Windows
dim oReg, objReg, strKeyPath, strValueName, strValue
dim strStringValueName, dwValue
const HKEY_CURRENT_USER = &H80000001
const HKEY_LOCAL_MACHINE = &H80000002
const HKEY_USERS = &H80000003
strComputer = "."
set oReg=GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & strComputer & "\root\default:StdRegProv")
set objReg=GetObject("winmgmts:\\" & strComputer & "\root\default:StdRegProv")
' Verificar a versão do Windows instalada
strKeyPath="SOFTWARE\Microsoft\Windows NT\CurrentVersion"
strValueName="ProductName"
oReg.GetStringValue HKEY_LOCAL_MACHINE,strKeyPath,strValueName,strValue
' CASO ----- Versão Windows XP
    if (strValue = "Microsoft Windows XP") = true then
      LSRUNAS="\\arapiraca\ocs\utilnet\execs\lsrunas.exe"
      INFO="/user:" & LOGIN & " " & "/password:" & PSSWD & " " & "/domain:" & DOMAIN & " " & "/command:"
      COMMAND="""wscript //B" & " " & """\\arapiraca\netlogon\logon_winxp.vbs"""""
      RUNPATH=" /n " & "/runpath:c:"
      strCmd=(LSRUNAS & " " & INFO & COMMAND & " " & RUNPATH)
      objShell.Run strCmd, 0
      WScript.Sleep 10000
    end if
' CASO ----- Versão Windows 7
    if (strValue = "Windows 7 Professional") = true then
      LSRUNAS="\\arapiraca\ocs\utilnet\execs\lsrunas.exe"
      INFO="/user:" & LOGIN & " " & "/password:" & PSSWD & " " & "/domain:" & DOMAIN & " " & "/command:"
      COMMAND="""wscript //B" & " " & """\\arapiraca\netlogon\logon_win7.vbs"""""
      RUNPATH=" /n " & "/runpath:c:"
      strCmd=(LSRUNAS & " " & INFO & COMMAND & " " & RUNPATH)
      objShell.Run strCmd, 0
      WScript.Sleep 10000
    end if

' CASO ----- Versão Windows 8
'    if (strValue = "Windows 8 Professional") = true then
'      LSRUNAS="\\arapiraca\ocs\utilnet\execs\lsrunas.exe"
'      INFO="/user:" & LOGIN & " " & "/password:" & PSSWD & " " & "/domain:" & DOMAIN & " " & "/command:"
'      COMMAND="""wscript //B" & " " & """\\arapiraca\netlogon\logon_win8.vbs"""""
'      RUNPATH=" /n " & "/runpath:c:"
'      strCmd=(LSRUNAS & " " & INFO & COMMAND & " " & RUNPATH)
'      objShell.Run strCmd, 0
'      WScript.Sleep 10000
'    end if

' Copiando e executando o BGINFO.
LSRUNAS="\\arapiraca\ocs\utilnet\execs\lsrunas.exe"
INFO="/user:" & LOGIN & " " & "/password:" & PSSWD & " " & "/domain:" & DOMAIN & " " & "/command:"
RUNPATH=" /n " & "/runpath:c:"
DIRBGINFO=WinDir & "\bginfo\"
BGINFOEXE=DIRBGINFO & "Bginfo.exe"
strBgi = "config.bgi"
strArguments = "/silent /nolicprompt /timer:0"
COMMAND="""xcopy /Y \\arapiraca\ocs\utilnet\bginfo\Bginfo.exe" & " " & DIRBGINFO & """"
strCmd=(LSRUNAS & " " & INFO & COMMAND & " " & RUNPATH)
objShell.Run strCmd, 0
COMMAND="""xcopy /Y \\arapiraca\ocs\utilnet\bginfo\config.bgi" & " " & DIRBGINFO & """"
strCmd=(LSRUNAS & " " & INFO & COMMAND & " " & RUNPATH)
objShell.Run strCmd, 0
WScript.Sleep 5000
strCmd = (BGINFOEXE & " " & DIRBGINFO & strBgi & " " & strArguments)
objShell.Run strCmd, 0

' Adicionando vbs para Acesso ao Servidor de arquivos da Tecnica
COMMAND="""xcopy /Y \\arapiraca\ocs\utilnet\files\tecnica.vbs" & " " & SystemRoot & """"
strCmd=(LSRUNAS & " " & INFO & COMMAND & " " & RUNPATH)
objShell.Run strCmd, 0

COMMAND=WinDir & "\startpage.bat"
strCmd=(COMMAND)
objShell.Run strCmd, 0

' Pána Inicial Firefox
COMMAND="""wscript //B" & " " & WinDir & "\firefox.vbs"""
strCmd=(COMMAND)
objShell.Run strCmd, 0

' Verificando setor do usuário
NUM=0
set objNetwork = CreateObject("WScript.Network")
strDomain = objNetwork.UserDomain
strUser = objNetwork.UserName
set objUser = GetObject("WinNT://" & strDomain & "/" & strUser)
for each objGroup in objUser.Groups
    NUM=NUM+1
    strGroupMemberships = strGroupMemberships & objGroup.Name
        if (num = 1) then
          SETOR=strGroupMemberships
        end if
next

' Mapear Unidades de Rede
dim FSODrive, WshNetwork
set WshNetwork=CreateObject("Wscript.Network")
set FSODrive = CreateObject("Scripting.FileSystemObject")
if FSODrive.DriveExists("K:") = true then
  WshNetwork.RemoveNetworkDrive "K:",true,true
  WshNetwork.MapNetworkDrive "K:","\\arapiraca\sistemas",true
else
  WshNetwork.MapNetworkDrive "K:","\\arapiraca\sistemas",true
end if
if FSODrive.DriveExists("G:") = true then
  WshNetwork.RemoveNetworkDrive "G:",true,true
  WshNetwork.MapNetworkDrive "G:","\\arapiraca\" & SETOR,true
else
  WshNetwork.MapNetworkDrive "G:","\\arapiraca\" & SETOR,true
end if

' Mensagem ao usuário
sADSPath= strDomain & "/" & strUser
set objUser = GetObject("WinNT://" & sADSPath & ",user")
if time <= "12:00:00" then
  MsgBox ("Bom dia "+objUser.FullName+", você acaba de ingressar na rede SESAU, por favor respeite as políticas de segurança")
elseif Time >= "12:00:01" and Time <= "18:00:00" then
  MsgBox ("Boa tarde "+objUser.FullName+", você acaba de ingressar na rede SESAU, por favor respeite as políticas de segurança")
else
  MsgBox ("Boa noite "+objUser.FullName+", você acaba de ingressar na rede SESAU, por favor respeite as políticas de segurança")
end if
 
Wscript.Quit 
