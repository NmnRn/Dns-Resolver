import pathlib, os

PROJECT_DIRECTORY = pathlib.Path(__file__).parent.resolve()

env_file = False

def control_env_file():
    global env_file
    fwd = PROJECT_DIRECTORY / ".env"
    if not fwd.exists():
        file = PROJECT_DIRECTORY.touch()
        with open(file, "w") as f:
            f.write(
                "UDP_PORT=53\n"
                "HTTPS_PORT=443\n"
                "QUIC_PORT=853\n"
                "LOG_DAYS=90\n"
                "CONTAINER_UDP_PORT=5300\n"
                "CONTAINER_HTTPS_PORT=44300\n"
                "CONTAINER_QUIC_PORT=85300\n"
                "DB_HOST=localhost\n"
                "DB_PORT=3306\n"
                "DB_USER=root\n"
                "DB_PASSWORD=password\n"
                "DB_NAME=dns_db\n"
                "DOMAIN=example.com\n"
                "SUB_DOMAIN=dns\n"
                "ALLOWED_HOST=dns.example.com\n"
                "ENABLE_UDP_SERVER=true\n"
                "ENABLE_HTTPS_SERVER=false\n"
                "CERT_FILE=no\n"
                "KEY_FILE=no\n"
                )
            f.close()