@echo off
set version=""
set /p version=«Î ‰»Î∞Ê±æ∫≈£∫
@echo %version%
if "%version%" neq "" set "version=--version-suffix %version%"
if not exist build md build
cd build
del *.nupkg
cd..
dotnet pack src\Wodsoft.EnhancedAuthentication.Core --output build %version%
dotnet pack src\Wodsoft.EnhancedAuthentication --output build %version%
dotnet pack src\Wodsoft.EnhancedAuthentication.MvcCore --output build %version%
dotnet pack src\Wodsoft.EnhancedAuthentication.Client --output build %version%
dotnet pack src\Wodsoft.EnhancedAuthentication.Client.AspNetCore --output build %version%
pause