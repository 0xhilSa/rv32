addi x10, x0, 15
addi x11, x0, 20
add x12, x10, x11
sub x13, x11, x10
and x14, x10, x11
or x15, x10, x11
xor x16, x10, x11
slli x17, x10, 2
srli x18, x11, 1

beq x10, x11, skip
addi x20, x0, 99

skip:
  addi x31, x0, 1
