@title Keycloak sync keystore
@echo off

@echo "Remember update storepass from the idbroker-updater-password.txt file"
@call set-env.bat
@call keytool -list -v -storepass jma8f379lhc6bughgl4e6a02cd -keystore idbroker-updater.jks

pause