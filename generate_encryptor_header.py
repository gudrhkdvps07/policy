with open("encryptor.exe", "rb") as f:
    data = f.read()

with open("encryptor_payload.h", "w") as f:
    f.write("unsigned char encryptor_exe[] = {\n")
    for i in range(0, len(data), 12):
        chunk = data[i:i+12]
        hex_line = ", ".join("0x{:02x}".format(b) for b in chunk)
        f.write("  " + hex_line + ",\n")
    f.write("};\n")
    f.write("unsigned int encryptor_exe_len = sizeof(encryptor_exe);\n")
