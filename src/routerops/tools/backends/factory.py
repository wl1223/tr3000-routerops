from routerops.config import Settings
from routerops.tools.backends.base import RouterBackend
from routerops.tools.backends.mock import MockRouterBackend
from routerops.tools.backends.ssh import ParamikoSSHAdapter


def build_backend(settings: Settings) -> RouterBackend:
    if settings.backend == "mock":
        return MockRouterBackend(settings.scenario)
    return ParamikoSSHAdapter(settings.device_profile())

