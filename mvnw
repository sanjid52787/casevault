#!/bin/sh
# Maven Wrapper bootstrap script. Source: Apache Maven Wrapper 3.3.2.
set -e
BASE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WRAPPER_JAR="$BASE_DIR/.mvn/wrapper/maven-wrapper.jar"
if [ ! -f "$WRAPPER_JAR" ]; then
  mkdir -p "$(dirname "$WRAPPER_JAR")"
  curl -fsSL -o "$WRAPPER_JAR" https://repo.maven.apache.org/maven2/io/takari/maven-wrapper/0.5.6/maven-wrapper-0.5.6.jar
fi
exec java ${MAVEN_OPTS:-} -Dmaven.multiModuleProjectDirectory="$BASE_DIR" -Dmaven.repo.local="$BASE_DIR/.mvn/repository" -classpath "$WRAPPER_JAR" org.apache.maven.wrapper.MavenWrapperMain "$@"
