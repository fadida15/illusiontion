"""Illusiontion package.

The deterministic core can be imported and tested without loading Google ADK.
The live agent is exposed lazily as ``app.root_agent`` when ADK is installed.
"""


def __getattr__(name: str):
    if name == "root_agent":
        from .agent import root_agent

        return root_agent
    raise AttributeError(name)


__all__ = ["root_agent"]
