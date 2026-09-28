"""Project package root.

`platform` collides with the stdlib module of the same name. Without an
__init__.py, `import platform.<sub>` resolves to the stdlib module and fails
("'platform' is not a package"); with an empty one, third-party code calling
`platform.system()` etc. breaks. So re-export the stdlib module's public API
here, which keeps both working.
"""
import importlib.util as _ilu
import os as _os
import sysconfig as _sysconfig

_spec = _ilu.spec_from_file_location(
    "_stdlib_platform", _os.path.join(_sysconfig.get_paths()["stdlib"], "platform.py")
)
_stdlib = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_stdlib)
globals().update({k: v for k, v in vars(_stdlib).items() if not k.startswith("__")})
