# Define project.
project('3gen', 'cpp', default_options: ['cpp_std=c++17', 'strip=true', 'buildtype=release',
                                   	 'optimization=3', 'cpp_eh=none'])
# Get C++ compiler.
cc = meson.get_compiler('cpp')
# Get the host's operating system.
os = host_machine.system()
# Default source files.
source    = ['main.cc', 'password_generator.cc']
include   = []
lib       = []
depends   = []
cpp_flags = []
is_gcc_compatible = (cc.get_id() == 'gcc' or cc.get_id() == 'clang')

# The define flag prefix is different on Windows with MSVC compiler.
if os == 'windows' and cc.get_id() == 'msvc'
	_Define_Flag_Prefix = '/D'
else
	_Define_Flag_Prefix = '-D'
endif

# Mac OSX
if   os == 'darwin'
	# On OSX, we use memset_s to securely zero over memory, thus we must define this macro.
	_flag = _Define_Flag_Prefix + '__STDC_WANT_LIB_EXT1__=1'
	cpp_flags += _flag
endif
# BSD OS's
if   os == 'openbsd' or os == 'freebsd' or os == 'darwin'
	include += '/usr/local/include'
	lib     += '/usr/local/lib'
	depends += cc.find_library('ncurses')
	depends += cc.find_library('ssc', dirs: lib)
# GNU/Linux
elif os == 'linux'
	if cc.get_id() == 'gcc'
		cpp_flags += '-flto'
	endif
	include += '/usr/include'
	depends += cc.find_library('ssc')
	depends += cc.find_library('ncurses')
	depends += cc.find_library('tinfo')
# Win64
elif os == 'windows'
	include += 'C:/include'
	lib     += 'C:/lib'
	depends += cc.find_library('bcrypt')
	depends += cc.find_library('ssc', static: true, dirs: lib)
	_flag      = _Define_Flag_Prefix + 'SSC_IMPORT_STATIC'
	cpp_flags += _flag
else
	assert(false)
endif
if is_gcc_compatible
	if get_option('enable_debugging_symbols')
		cpp_flags += '-g'
	endif
endif

if os != 'windows'
	executable('3gen', sources: source, dependencies: depends,
		   include_directories: include, install: true,
		   cpp_args: cpp_flags)
else
	executable('3gen', sources: source, dependencies: depends,
	           include_directories: include, install: true,
		   cpp_args: cpp_flags, install_dir: 'C:/bin')
endif
