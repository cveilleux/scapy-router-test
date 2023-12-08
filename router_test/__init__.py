import logging
import subprocess
import sys
import random


class InfoFilter(logging.Filter):
    def filter(self, rec):
        return rec.levelno in (logging.DEBUG, logging.INFO)


def get_logger(name):
    formatter = logging.Formatter("%(asctime)s %(levelname)-8s %(message)s",  "%Y-%m-%d %H:%M:%S")

    logger = logging.getLogger(name)
    logger.handlers = []
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    h1 = logging.StreamHandler(sys.stdout)
    h1.setLevel(logging.INFO)
    h1.addFilter(InfoFilter())
    h1.setFormatter(formatter)
    h2 = logging.StreamHandler(sys.stderr)
    h2.setLevel(logging.WARNING)
    h2.setFormatter(formatter)

    logger.addHandler(h1)
    logger.addHandler(h2)

    return logger


logger = get_logger("main")


def random_string(len):
    return "".join(
        random.SystemRandom().choice("abcdefghijkmnpqrstuvwxyz23456789") for _ in range(len)
    )


def run(cmd, **kwargs) -> "subprocess.CompletedProcess":
    """
    Execute command. If it crashes, logs the stdout output and re-raise the CalledProcessError.
    """
    logger.debug("Executing: {0}".format(" ".join(cmd)))
    if "encoding" not in kwargs:
        kwargs["encoding"] = "utf-8"

    check = kwargs.pop("check", True)

    result = subprocess.run(cmd, check=False, capture_output=True, **kwargs)
    if result.returncode:
        output = result.stderr
        if output.strip() == "":
            output = "(Process returned nothing to stderr)"

        if check:
            logger.error(
                'Command "{0}" failed with exit code {1}: {2}'.format(
                    " ".join(cmd), result.returncode, output
                )
            )
            result.check_returncode()

        else:
            logger.warning(
                'Command "{0}" failed with exit code {1}: {2}'.format(
                    " ".join(cmd), result.returncode, output
                )
            )

    return result


def run_and_get_output(cmd, **kwargs):
    result = run(cmd, **kwargs)
    return result.stdout


