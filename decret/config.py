import os

DEBIAN_RELEASES = [
    "woody",
    "sarge",
    "etch",
    "lenny",
    "squeeze",
    "wheezy",
    "jessie",
    "stretch",
    "buster",
    "bullseye",
    "bookworm",
    "trixie",  # This one just helps find information easier
]

DEFAULT_PACKAGES = ["aptitude", "nano", "adduser"]

BEEFY_PACKAGES = [
    "vim",
    "less",
    "wget",
    "net-tools",
    "psmisc",
    "procps",
    "iproute2",
    "strace",
]

SUPPORTED_RELEASES = DEBIAN_RELEASES[-3:]

LATEST_RELEASE = DEBIAN_RELEASES[-1]

DEFAULT_TIMEOUT = 10

DOCKER_SHARED_DIR = "/tmp/decret"

RUNS_ON_GITHUB_ACTIONS = os.getenv("GITHUB_ACTIONS") == "true"


class FatalError(BaseException):
    pass


class CVENotFound(BaseException):
    pass
