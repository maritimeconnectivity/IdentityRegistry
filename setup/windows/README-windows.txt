MIR WINDOWS

        These scripts are created to help setup MIR in a windows developer environment.
        Scripts assumes that the http services are run at localhost.

ENV

        This is default environment, edit the set-env.bat to change values.

    Environment Variables

        MCP_RUNTIME_HOME	c:/work/mcp/runtime
        JAVA_HOME		%MCP_RUNTIME_HOME%\openjdk-8u272-b10
        MYSQL_HOME		%MCP_RUNTIME_HOME%\mariadb-10.5.7-winx64

    Services

        IR: 		http://localhost:8444
        Keycloak:	http://localhost:8080

SETUP

        1. Create copy of the set-env.template and rename it to set-env.bat
        2. Update set-env.bat to match your environment