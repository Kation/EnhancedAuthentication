@echo off
set version=
set /p version=«Î ‰»Î∞Ê±æ∫≈£∫
@echo %version%
if "%version%" neq "" set "version=--version-suffix %version%"
if not exist build md build
cd build
del *.nupkg
cd..
dotnet pack src\Wodsoft.EnhancedAuthentication.Core --output ..\..\build --include-source %version%
dotnet pack src\Wodsoft.EnhancedAuthentication --output ..\..\build --include-source %version%
dotnet pack src\Wodsoft.EnhancedAuthentication.MvcCore --output ..\..\build --include-source %version%
dotnet pack src\Wodsoft.EnhancedAuthentication.Client --output ..\..\build --include-source %version%
dotnet pack src\Wodsoft.EnhancedAuthentication.Client.AspNetCore --output ..\..\build --include-source %version%
pause