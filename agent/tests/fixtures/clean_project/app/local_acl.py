def set_reader_access(path, access):
    pass
def configure(runtime):
    set_reader_access(runtime, 'read')
    set_reader_access(runtime / 'keys', 'none')
    set_reader_access(runtime / 'journal', 'none')
    set_reader_access(runtime / 'journal' / 'pending', 'none')
    set_reader_access(runtime / 'journal' / 'received', 'none')
