"""
RISC-V Assembly to Hexa/Binary Decimal Converter
Converts RISC-V assembly instructions to hexadecimal machine code
"""
from multipledispatch import dispatch

class RISCVAssembler:
  def __init__(self):
    self.reg_map = {
      'x0': 0, 'zero': 0, 'x1': 1, 'ra': 1, 'x2': 2, 'sp': 2, 'x3': 3, 'gp': 3,
      'x4': 4, 'tp': 4, 'x5': 5, 't0': 5, 'x6': 6, 't1': 6, 'x7': 7, 't2': 7,
      'x8': 8, 's0': 8, 'fp': 8, 'x9': 9, 's1': 9, 'x10': 10, 'a0': 10,
      'x11': 11, 'a1': 11, 'x12': 12, 'a2': 12, 'x13': 13, 'a3': 13,
      'x14': 14, 'a4': 14, 'x15': 15, 'a5': 15, 'x16': 16, 'a6': 16,
      'x17': 17, 'a7': 17, 'x18': 18, 's2': 18, 'x19': 19, 's3': 19,
      'x20': 20, 's4': 20, 'x21': 21, 's5': 21, 'x22': 22, 's6': 22,
      'x23': 23, 's7': 23, 'x24': 24, 's8': 24, 'x25': 25, 's9': 25,
      'x26': 26, 's10': 26, 'x27': 27, 's11': 27, 'x28': 28, 't3': 28,
      'x29': 29, 't4': 29, 'x30': 30, 't5': 30, 'x31': 31, 't6': 31
    }
    self.instructions = None
    self.labels = {}

  @dispatch(str)
  def __getitem__(self, address): #type: ignore
    if self.instructions is None: raise ValueError("No instructions were given!")
    for line in self.instructions:
      if line["address"] == address:
        string = f"""
{'='*105}
{'Line':<6} {'Address':<12} {'Instruction':<30} {'Hex Code':<12} {'Binary Code':<12} \t\t\t   {'Status':<20}
{'='*105}
{line['line']:<6} {line['address']:<12} {line['instruction']:<30} {line['hex']:<12} {line['binary']:<12}   {'OK':<20}
        """
        return string
      else: continue
    raise ValueError(f"Invalid Address: {address}")

  @dispatch(int)
  def __getitem__(self, line_no):
    if self.instructions is None: raise ValueError("No instructions were given!")
    for line in self.instructions:
      if int(line["line"]) == line_no:
        string = f"""
{'='*105}
{'Line':<6} {'Address':<12} {'Instruction':<30} {'Hex Code':<12} {'Binary Code':<12} \t\t\t   {'Status':<20}
{'='*105}
{line['line']:<6} {line['address']:<12} {line['instruction']:<30} {line['hex']:<12} {line['binary']:<12}   {'OK':<20}
        """
        return string
      else: continue
    raise ValueError(f"Number Line: {line_no}")

  def get_reg(self, reg_str):
    """Convert register name to number"""
    reg_str = reg_str.strip().lower()
    if reg_str in self.reg_map: return self.reg_map[reg_str]
    try: return int(reg_str)
    except: raise ValueError(f"Invalid register: {reg_str}")

  def sign_extend(self, value, bits):
    """Sign extend a value to 32 bits"""
    sign_bit = 1 << (bits - 1)
    return (value & (sign_bit - 1)) - (value & sign_bit)

  def encode_r_type(self, opcode, rd, funct3, rs1, rs2, funct7):
    """Encode R-type instruction"""
    instr = (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
    return instr & 0xFFFFFFFF

  def encode_i_type(self, opcode, rd, funct3, rs1, imm):
    """Encode I-type instruction"""
    imm = imm & 0xFFF
    instr = (imm << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
    return instr & 0xFFFFFFFF

  def encode_s_type(self, opcode, funct3, rs1, rs2, imm):
    """Encode S-type instruction"""
    imm11_5 = (imm >> 5) & 0x7F
    imm4_0 = imm & 0x1F
    instr = (imm11_5 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (imm4_0 << 7) | opcode
    return instr & 0xFFFFFFFF

  def encode_b_type(self, opcode, funct3, rs1, rs2, imm):
    """Encode B-type instruction"""
    imm12 = (imm >> 12) & 0x1
    imm10_5 = (imm >> 5) & 0x3F
    imm4_1 = (imm >> 1) & 0xF
    imm11 = (imm >> 11) & 0x1
    instr = (imm12 << 31) | (imm10_5 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (imm4_1 << 8) | (imm11 << 7) | opcode
    return instr & 0xFFFFFFFF

  def encode_u_type(self, opcode, rd, imm):
    """Encode U-type instruction"""
    instr = ((imm & 0xFFFFF) << 12) | (rd << 7) | opcode
    return instr & 0xFFFFFFFF

  def encode_j_type(self, opcode, rd, imm):
    """Encode J-type instruction"""
    imm20 = (imm >> 20) & 0x1
    imm10_1 = (imm >> 1) & 0x3FF
    imm11 = (imm >> 11) & 0x1
    imm19_12 = (imm >> 12) & 0xFF
    instr = (imm20 << 31) | (imm10_1 << 21) | (imm11 << 20) | (imm19_12 << 12) | (rd << 7) | opcode
    return instr & 0xFFFFFFFF

  def parse_instruction(self, line, current_addr):
    """Parse a single instruction and return machine code"""
    line = line.strip().lower()
    # remove comments
    if '#' in line: line = line[:line.index('#')]
    line = line.strip()
    if not line:
      return None
    # split instruction and operands
    parts = []
    temp = line.replace(',', ' ').replace('(', ' ').replace(')', ' ')
    for part in temp.split():
      if part: parts.append(part)
    if not parts: return None
    instr = parts[0]
    # R-Type Instructions
    r_type_configs = {
      'add': (0x33, 0x0, 0x00),
      'sub': (0x33, 0x0, 0x20),
      'and': (0x33, 0x7, 0x00),
      'or': (0x33, 0x6, 0x00),
      'xor': (0x33, 0x4, 0x00),
      'sll': (0x33, 0x1, 0x00),
      'srl': (0x33, 0x5, 0x00),
      'sra': (0x33, 0x5, 0x20),
      'slt': (0x33, 0x2, 0x00),
      'sltu': (0x33, 0x3, 0x00),
    }
    if instr in r_type_configs:
      opcode, funct3, funct7 = r_type_configs[instr]
      rd = self.get_reg(parts[1])
      rs1 = self.get_reg(parts[2])
      rs2 = self.get_reg(parts[3])
      return self.encode_r_type(opcode, rd, funct3, rs1, rs2, funct7)
    # I-Type Arithmetic Instructions
    i_type_arith = {
      'addi': 0x0, 'andi': 0x7, 'ori': 0x6, 'xori': 0x4, 'slti': 0x2, 'sltiu': 0x3
    }
    if instr in i_type_arith:
      rd = self.get_reg(parts[1])
      rs1 = self.get_reg(parts[2])
      imm = int(parts[3], 0)
      return self.encode_i_type(0x13, rd, i_type_arith[instr], rs1, imm)
    # I-Type Shift Instructions with Immediate
    if instr in ['slli', 'srli', 'srai']:
      rd = self.get_reg(parts[1])
      rs1 = self.get_reg(parts[2])
      shamt = int(parts[3], 0) & 0x1F
      if instr == 'slli':
        funct3 = 0x1
        imm = shamt
      elif instr == 'srli':
        funct3 = 0x5
        imm = shamt
      else:  # srai
        funct3 = 0x5
        imm = 0x400 | shamt
      return self.encode_i_type(0x13, rd, funct3, rs1, imm)
    # Load Instructions
    load_configs = {
      'lb': 0x0, 'lh': 0x1, 'lw': 0x2, 'lbu': 0x4, 'lhu': 0x5
    }
    if instr in load_configs:
      rd = self.get_reg(parts[1])
      imm = int(parts[2], 0)
      rs1 = self.get_reg(parts[3])
      return self.encode_i_type(0x03, rd, load_configs[instr], rs1, imm)
    # Store Instructions
    store_configs = {
      'sb': 0x0, 'sh': 0x1, 'sw': 0x2
    }
    if instr in store_configs:
      rs2 = self.get_reg(parts[1])
      imm = int(parts[2], 0)
      rs1 = self.get_reg(parts[3])
      return self.encode_s_type(0x23, store_configs[instr], rs1, rs2, imm)
    # Branch Instructions
    branch_configs = {
      'beq': 0x0, 'bne': 0x1, 'blt': 0x4, 'bge': 0x5, 'bltu': 0x6, 'bgeu': 0x7
    }
    if instr in branch_configs:
      rs1 = self.get_reg(parts[1])
      rs2 = self.get_reg(parts[2])
      target = parts[3]
      # Check if target is a label or immediate
      if target in self.labels: imm = self.labels[target] - current_addr
      else: imm = int(target, 0)
      return self.encode_b_type(0x63, branch_configs[instr], rs1, rs2, imm)
    # LUI and AUIPC
    if instr == 'lui':
      rd = self.get_reg(parts[1])
      imm = int(parts[2], 0)
      return self.encode_u_type(0x37, rd, imm)
    if instr == 'auipc':
      rd = self.get_reg(parts[1])
      imm = int(parts[2], 0)
      return self.encode_u_type(0x17, rd, imm)
    # JAL
    if instr == 'jal':
      rd = self.get_reg(parts[1])
      target = parts[2]
      if target in self.labels: imm = self.labels[target] - current_addr
      else: imm = int(target, 0)
      return self.encode_j_type(0x6F, rd, imm)
    # JALR
    if instr == 'jalr':
      rd = self.get_reg(parts[1])
      imm = int(parts[2], 0)
      rs1 = self.get_reg(parts[3])
      return self.encode_i_type(0x67, rd, 0x0, rs1, imm)
    raise ValueError(f"Unsupported instruction: {instr}")
  def assemble(self, assembly_code):
    """Assemble RISC-V assembly code to machine code"""
    lines = assembly_code.strip().split('\n')
    addr = 0
    for line in lines:
      line = line.strip()
      if ':' in line and not line.startswith('#'):
        label = line.split(':')[0].strip().lower()
        self.labels[label] = addr
      elif line and not line.startswith('#'): addr += 4
    results = []
    addr = 0
    for line_num, line in enumerate(lines, 1):
      original_line = line.strip()
      if ':' in original_line: original_line = original_line.split(':', 1)[1].strip()
      if not original_line or original_line.startswith('#'): continue
      try:
        machine_code = self.parse_instruction(original_line, addr)
        if machine_code is not None:
          hex_code = f"0x{machine_code:08X}"
          binary_code = f"0b{machine_code:032b}"
          results.append({
            'line': line_num,
            'address': f"0x{addr:08X}",
            'instruction': original_line,
            'hex': hex_code,
            'binary': binary_code,
            'error': None
          })
          addr += 4
      except Exception as e:
        results.append({
          'line': line_num,
          'address': f"0x{addr:08X}",
          'instruction': original_line,
          'hex': None,
          'binary': None,
          'error': str(e)
        })
    self.instructions = results
    return self.instructions

def print_results(results):
  """Print assembly results in a formatted table"""
  print("\n" + "="*105)
  print(f"{'Line':<6} {'Address':<12} {'Instruction':<30} {'Hex Code':<12} {'Binary Code':<12} \t\t\t   {'Status':<20}")
  print("="*105)
  for result in results:
    if result['error']: print(f"{result['line']:<6} {result['address']:<12} {result['instruction']:<30} {'ERROR':<12} {result['error']}")
    else:
      print(f"{result['line']:<6} {result['address']:<12} {result['instruction']:<30} {result['hex']:<12} {result['binary']:<12}   {'OK':<20}")
  print("="*105 + "\n")

def export_hex(results, filename="a.hex"):
  lines = []
  for r in results:
    if r["error"] is None and r["hex"] is not None:
      hex_value = r["hex"][2:]
      lines.append(hex_value)
  output = "\n".join(lines)
  if filename:
    with open(filename, "w") as f: f.write(output)
  return output

def export_bin(results, filename="a.bin"):
  lines = []
  for r in results:
    if r["error"] is None and r["binary"] is not None:
      bin_value = r["binary"][2:]
      lines.append(bin_value)
  output = "\n".join(lines)
  if filename:
    with open(filename, "w") as f: f.write(output)
  return output
