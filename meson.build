project('rz-bindgen', 'c', 'cpp')

pymod = import('python')
py = pymod.find_installation('python')

clang_path = get_option('clang_path')
clang_args = get_option('clang_args')
rizin_include_path = get_option('rizin_include_path')
targets = get_option('targets')

target_swig = targets.contains('SWIG')
target_sphinx = targets.contains('sphinx')

doxygen_path = get_option('doxygen_path')

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

if rizin_include_path == ''
  rz_main = dependency('rz_main')
  if rz_main.type_name() == 'pkgconfig'
    rizin_include_path = rz_main.get_variable(pkgconfig: 'includedir') / 'librz'
  elif rz_main.type_name() == 'cmake'
    rizin_include_path = rz_main.get_variable(cmake: 'PACKAGE_INCLUDE_DIRS').split(';')[0]
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

bindgen_output_names = []
if target_swig
  swig_source_idx = bindgen_output_names.length()
  bindgen_output_names += ['rizin.i']
endif

if target_sphinx
  sphinx_dir_idx = bindgen_output_names.length()
  bindgen_output_names += ['sphinx']
endif

bindgen_outputs = custom_target(
  'bindgen_outputs',
  input: 'src' / 'main.py',
  output: bindgen_output_names,
  command: [
    py, '@INPUT@',
    '-o', '@OUTDIR@',
    '--clang-path', clang_path,
    '--clang-args', clang_args,
    '--rizin-include-path', rizin_include_path,
    '--targets', ','.join(targets)
  ] + (doxygen_path != '' ? ['--doxygen-path', doxygen_path] : [])
)

if target_swig
  swig_output = custom_target(
    'swig_output',
    input: bindgen_outputs[swig_source_idx],
    output: ['rizin.py', 'rizin_wrap.cxx'],
    command: [
      find_program('swig'),
      '-python', '-c++',
      '-outdir', '@OUTDIR@', '@INPUT@'
    ],
    install: true,
    install_dir: [py.get_install_dir(), false]
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
      rizin_include_path,
      rizin_include_path / 'sdb'
    ),
    install: true
  )
endif

if target_sphinx
  custom_target(
    'sphinx',
    input: bindgen_outputs[sphinx_dir_idx],
    output: 'sphinx_output',
    command: [
      find_program('sphinx-build'),
      '@INPUT@',
      '@OUTPUT@'
    ],
    build_by_default: true
  )
endif

if get_option('plugin').enabled()
  subdir('plugin')
endif
