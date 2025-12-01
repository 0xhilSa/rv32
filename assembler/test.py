from rv32assembler import RISCVAssembler, export_bin, export_hex

asm = RISCVAssembler()
with open("./test.asm", "r") as file:
  content = file.read()
  res = asm.assemble(content)
  export_bin(res)
  export_hex(res)
print(asm["0x00000008"])
print(asm[3])
