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
                )
            f.close()