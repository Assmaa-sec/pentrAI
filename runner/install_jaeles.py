"""Install the upstream Jaeles release with a verified archive digest."""

from install_binaries import install


if __name__ == "__main__":
    install(
        "jaeles",
        "https://github.com/jaeles-project/jaeles/releases/download/beta-v0.17/jaeles-v0.17-linux.zip",
        "7eb6bd59c0cdb817f9126b4064e8277e96d44e8414ba076e5ec560e63bb76221",
        "jaeles",
    )
