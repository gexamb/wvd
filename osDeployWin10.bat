REM *****  STEP 1 OF 1 OF OS DEPLOYMENT  *****

cd %~dp0

powershell.exe -ExecutionPolicy Bypass -File ".\osdeployWin10.ps1" -patch 1

VMwareOSOptimizationTool.exe -o -t .\CSUN_WinSys_Win10.xml -v > osotlog.txt 2>&1

shutdown /f /r /t 10