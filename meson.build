project('aes', 'c', license : 'GPL3')
aes_lib = library('aes', 'aes.c', install : true)
aes_test = executable('aes_test', 'test.c', link_with: aes_lib)
test('AES AVS tests', aes_test)
