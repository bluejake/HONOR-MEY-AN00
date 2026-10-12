import zipfile
Z = r"<HOME>/WorkBuddy/2026-09-26-09-04-37/MEY-AN00 10.0.0.175(C00E170R404P2)_Firmware_MagicOS 10.0_0501AJAB.zip"
z = zipfile.ZipFile(Z)
for i in z.infolist():
    print('%14d  %12d  %s' % (i.file_size, i.compress_size, i.filename))
