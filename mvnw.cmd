@ECHO OFF
SETLOCAL
SET "WRAPPER_JAR=%~dp0.mvn\wrapper\maven-wrapper.jar"
IF NOT EXIST "%WRAPPER_JAR%" (
  powershell -NoProfile -Command "Invoke-WebRequest -UseBasicParsing -Uri 'https://repo.maven.apache.org/maven2/io/takari/maven-wrapper/0.5.6/maven-wrapper-0.5.6.jar' -OutFile '%WRAPPER_JAR%'"
)
java -Dmaven.multiModuleProjectDirectory="%CD%" -classpath "%WRAPPER_JAR%" org.apache.maven.wrapper.MavenWrapperMain %*
ENDLOCAL
