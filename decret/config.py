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
AVAILABLE_ON_MAIN_SITE = DEBIAN_RELEASES[-5:]

LATEST_RELEASE = DEBIAN_RELEASES[-1]

DEFAULT_TIMEOUT = 10

DOCKER_SHARED_DIR = "/tmp/decret"

RUNS_ON_GITHUB_ACTIONS = os.getenv("GITHUB_ACTIONS") == "true"


class FatalError(BaseException):
    pass


class CVENotFound(BaseException):
    pass
