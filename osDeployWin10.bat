REM *****  STEP 1 OF 1 OF OS DEPLOYMENT  *****

cd %~dp0

powershell.exe -ExecutionPolicy Bypass -File ".\osdeployWin10.ps1" -patch 1

VMwareOSOptimizationTool.exe -o -t .\CSUN_WinSys_Win10.xml -v > C:\Packages\osotlog.txt 2>&1