from . import config
import os

# qlpack content writter
qlpack_content = '''
name: uac
version: 0.0.3
libraryPathDependencies: [codeql-cpp]
'''
qlpack_path = os.path.join(config.tmp_path, 'qlpack.yml')
open(qlpack_path, 'w').write(qlpack_content)
