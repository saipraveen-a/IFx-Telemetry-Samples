rem Ensure that the scope is the directory of the HealthExtension
pushd %~dp0
HealthExtension.Native.exe %*
