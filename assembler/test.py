from rv32assembler import RISCVAssembler, export_bin, export_hex, print_results

asm = RISCVAssembler()
with open("./test.asm", "r") as file:
  content = file.read()
  res = asm.assemble(content)
  export_bin(res)
  export_hex(res)
  print_results(res)
