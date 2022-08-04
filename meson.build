project('rz-bindgen', 'c', 'cpp')

pymod = import('python')
py = pymod.find_installation('python')

clang_path = get_option('clang_path')
clang_args = get_option('clang_args')
rizin_inc_path = get_option('rizin_inc_path')

doxygen_html_path = get_option('doxygen_html_path')
sphinx_enabled = doxygen_html_path != ''

if clang_path == ''
  llvm = dependency('llvm', required: false)
  if llvm.found()
    clang_path = llvm.get_variable(configtool: 'libdir', default_value: 'none')
  elif build_machine.system() == 'darwin'
    clang_path = '/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/'
  elif build_machine.system() == 'windows'
    clang_path = import('fs').parent(find_program('clang.exe').full_path())
  else
    clang_path = '/usr/lib/'
  endif
endif

if rizin_inc_path == ''
  rz_main = dependency('rz_main')
  if rz_main.type_name() == 'pkgconfig'
    rizin_inc_path = rz_main.get_variable(pkgconfig: 'includedir') / 'librz'
  elif rz_main.type_name() == 'cmake'
    rizin_inc_path = rz_main.get_variable(cmake: 'PACKAGE_INCLUDE_DIRS').split(';')[0]
  endif
endif

if clang_args == ''
  clang = find_program('clang', 'clang-7', required: false)
  if clang.found()
    clang_args += ' -resource-dir='
    clang_args += run_command(clang, '-print-resource-dir').stdout().strip()
  endif
  if build_machine.system() == 'darwin'
    clang_args += ' -isysroot /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk'
  endif
endif

swig_sources = custom_target(
  'swig_sources',
  input: 'src' / 'main.py',
  output: ['rizin.i'] + (sphinx_enabled ? ['sphinx'] : []),
  command: [
    py, '@INPUT@',
    '-o', '@OUTDIR@',
    '--clang-path', clang_path,
    '--clang-args', clang_args,
    '--rizin-inc-path', rizin_inc_path
  ] + (sphinx_enabled ? ['--doxygen-html-path', doxygen_html_path] : [])
)

swig_output = custom_target(
  'swig_output',
  input: swig_sources[0],
  depend_files: ['src' / 'rizin_pre.i', 'src' / 'rizin_post.i'],
  output: ['rizin.py', 'rizin_wrap.cxx'],
  command: [
    find_program('swig'),
    '-python',
    '-I' + meson.current_source_dir() / 'src',
    '-c++',
    '-outdir', '@OUTDIR@', '@INPUT@'
  ],
  install: true,
  install_dir: [false, py.get_install_dir()]
)
swig_py = swig_output[0]
swig_wrap = swig_output[1]

py.extension_module(
  '_rizin',
  swig_wrap,
  dependencies: [
    py.dependency(),
    dependency('openssl', required: false),
    dependency('rz_main')
  ],
  include_directories: include_directories(
    rizin_inc_path,
    rizin_inc_path / 'sdb'
  ),
  install: true
)

if get_option('plugin').enabled()
  subdir('plugin')
endif

if sphinx_enabled
  custom_target(
    'sphinx',
    input: swig_sources[1],
    output: 'sphinx_output',
    command: [
      find_program('sphinx-build'),
      '@INPUT@',
      '@OUTPUT@'
    ]
  )
endif
