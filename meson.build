project('3gen', 'c', default_options: ['c_std=c17', 'optimization=3', 'buildtype=release', 'strip=true'])

_PROJECT = '3gen'
_LANG = 'c'

_UNIXLIKE_OPERATING_SYSTEMS  = ['openbsd', 'freebsd', 'netbsd', 'darwin', 'linux']
_SUPPORTED_OPERATING_SYSTEMS = _UNIXLIKE_OPERATING_SYSTEMS + ['windows']
_GCC_COMPATIBLE_COMPILERS    = ['gcc', 'clang']
_SUPPORTED_COMPILERS         = _GCC_COMPATIBLE_COMPILERS + ['msvc']

compiler = meson.get_compiler(_LANG)
os = host_machine.system()
SSC_static = get_option('SSC_static')
SSC_mlock  = get_option('SSC_mlock')
PPQ_static  = get_option('PPQ_static')

assert (os in _SUPPORTED_OPERATING_SYSTEMS, 'You are trying to build symm using an unsupported operating system!')
assert (compiler.get_id() in _SUPPORTED_COMPILERS, 'You are trying to build symm using an unsupported compiler!')

if os == 'windows' and compiler.get_id() == 'msvc'
	_D = '/D'
else
	_D = '-D'
endif

src = [
  'CommandLineArg.c',
  'Threegen.c',
  'Main.c'
  ]
# Setup these empty arrays that we will be appending to depending on OS, etc.
lib_deps   = []
lang_flags = []
inc_dir    = []
# Determine flags to pass to gcc-compatible compilers.
gcc_compatible_flags = [
  '-fvisibility=hidden',
  '-fstrict-aliasing',
  '-Wall',
  '-funroll-loops'
  ]
if SSC_static
  lang_flags += _D + 'SSC_EXTERN_STATIC_LIB'
endif
if PPQ_static
  lang_flags += _D + 'PPQ_EXTERN_STATIC_LIB'
endif
if os != 'netbsd' and compiler.get_id() != 'clang'
  gcc_compatible_flags += '-flto'
endif

if os == 'darwin' # On MacOS we require __STDC_WANT_LIB_EXT1__ to be defined as 1, for access to memset_s.
  lang_flags += _D + '__STDC_WANT_LIB_EXT1__=1'
endif

if os in _UNIXLIKE_OPERATING_SYSTEMS
  if get_option('native_optimize')
    lang_flags += '-march=native'
  endif
  if compiler.get_id() in _GCC_COMPATIBLE_COMPILERS
    lang_flags += gcc_compatible_flags
  endif
endif

if os in _UNIXLIKE_OPERATING_SYSTEMS and compiler.get_id() in _GCC_COMPATIBLE_COMPILERS
  lang_flags += gcc_compatible_flags
endif

if os in ['darwin', 'freebsd', 'openbsd']
  lib_deps += compiler.find_library('SSC', static: SSC_static, dirs: '/usr/local/lib')
  lib_deps += compiler.find_library('PPQ', static: PPQ_static, dirs: '/usr/local/lib')
elif os == 'windows'
  lib_deps += compiler.find_library('SSC', static: SSC_static, dirs: 'C:\lib')
  lib_deps += compiler.find_library('PPQ', static: PPQ_static, dirs: 'C:\lib')
else
  lib_deps += compiler.find_library('SSC', static: SSC_static)
  lib_deps += compiler.find_library('PPQ', static: PPQ_static)
endif

if SSC_static and os in _UNIXLIKE_OPERATING_SYSTEMS
  lib_deps += compiler.find_library('ncurses')
  if os == 'linux'
    lib_deps += compiler.find_library('tinfo')
  endif
endif

if SSC_mlock and os != 'openbsd'
  lang_flags += _D + 'SSC_EXTERN_MEMLOCK'
endif

inc_dir += '..'

if get_option('strict_arg_processing')
  lang_flags += _D + 'THREEGEN_EXTERN_STRICT_ARG_PROCESSING'
endif


if os == 'windows'
  executable('3gen', sources: src, dependencies: lib_deps,
	     c_args: lang_flags, include_directories: 'C:/include',
	     install: true, install_dir: 'C:/bin')
else
  assert (os in _UNIXLIKE_OPERATING_SYSTEMS, 'This branch covers unixlike operating systems.')
  executable('3gen', sources: src, dependencies: lib_deps,
	     c_args: lang_flags, include_directories: inc_dir,
	     install: true )
endif
