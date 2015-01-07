rem git clone https://git.chromium.org/external/gyp.git build/gyp
set PYTHON=python.exe

set config=
set target=Build
set noprojgen=
set nobuild=
set run=
set target_arch=ia32
set vs_toolset=x86
set platform=WIN32
set library=static_library


"%PYTHON%" gyp_http.py -Dtarget_arch=%target_arch% -Duv_library=%library%
