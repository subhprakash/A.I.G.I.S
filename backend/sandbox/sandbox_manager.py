import os


def prepare_scan_environment(path):

    if not os.path.exists(path):
        raise Exception("Scan target not found")

    return True