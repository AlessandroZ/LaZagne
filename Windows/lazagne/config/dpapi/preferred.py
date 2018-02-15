import struct

# From https://github.com/Fist0urs/JohnTheRipper/blob/4be0413da944c2cb3748fdff72dcb48131390d2d/run/DPAPImk2john.py
def display_masterkey(Preferred):
    GUID1 = Preferred.read(8)
    GUID2 = Preferred.read(8)

    GUID  = struct.unpack("<LHH", GUID1)
    GUID2 = struct.unpack(">HLH", GUID2)

    return "%s-%s-%s-%s-%s%s" % (format(GUID[0], 'x'), format(GUID[1], 'x'), format(GUID[2], 'x'), format(GUID2[0], 'x'), format(GUID2[1], 'x'), format(GUID2[2], 'x'))
 
