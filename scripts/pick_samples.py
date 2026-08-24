#!/usr/bin/env python3
"""Pick a stratified sample of decompiled .c files for compile testing."""
import random
from pathlib import Path
d = Path('src_out/empire.retail.dll/decomp')
files = [str(p).replace('\\','/') for p in d.glob('*.c')]
random.seed(42)
sample = random.sample(files, 200)
print('\n'.join(sample))
