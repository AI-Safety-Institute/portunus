# Native dependency notices

The runtime uses [uvloop 0.22.1](https://pypi.org/project/uvloop/0.22.1/) and
[hiredis 3.3.0](https://pypi.org/project/hiredis/3.3.0/). Their binary wheels
include native libraries: libuv and the hiredis C library, respectively.

These notices come from the source distributions matching the locked versions.
They supplement the licenses installed with each Python distribution and travel
with the Portunus package in its wheel and container image. Recheck the bundled
libraries and notices when updating either dependency.
