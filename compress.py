import tarfile


def compression(source, target=None):
    if target is None:
        target = '%s.tar.bz2' % source
    archive = tarfile.open(target, 'w:bz2')
    # archive.debug = 1

    archive.add(source, source.split('\\')[-1])
    archive.close()
    return target


def decompression(source, target):
    tar = tarfile.open(source, "r:bz2")
    file_names = tar.getnames()
    for file_name in file_names:
        tar.extract(file_name, target)
    tar.close()


print(compression('E:\\PycharmProjects\\test'))  # compression dir save to E:\PycharmProjects\test.tar.bz2
decompression('E:\\PycharmProjects\\test.tar.bz2', target='e:\\')  # decompression dir to e:\\test
