"""Completed subprocess adapter for existing private-tool unit fixtures."""


def completed(result):
    result.poll = lambda: result.returncode
    result.wait = lambda **kwargs: result.returncode
    result.kill = lambda: None
    return result
