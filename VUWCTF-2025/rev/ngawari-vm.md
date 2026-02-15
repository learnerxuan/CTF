---
ctf: VUWCTF 2025
category: rev
difficulty: easy
points: 176
flag: "VuwCTF{VuwCTF_1s_s0_c00l_innit}"
techniques: [pushdown_automaton, vm_analysis, bfs]
tools: [python]
---

# Ngawari VM

## Description
A custom VM that implements a Pushdown Automaton (PDA) - a state machine with a stack. It reads bytecode from `flag_checker.txt` and validates user input.

## Solution

### VM Format

- **First line**: `<initial_state><initial_stack_symbol><accepting_states>`
- **Instruction lines**: `<state><input><stack_top><new_state><push_chars>`

### Solution Approach

1. Parsed the PDA instructions from the bytecode file
2. Used BFS to find an input string that successfully transitions through the automaton and ends in accepting state

### Solver (Key Part)

```python
from collections import deque

queue = deque([(initial_state, (initial_stack,), "")])
while queue:
    state, stack, input_str = queue.popleft()
    for (cs, ic, st, ns, pc) in instructions:
        if cs == state and st == stack[-1]:
            new_stack = list(stack[:-1])
            for c in reversed(pc):
                new_stack.append(c)
            if ic == '^' and ns in accepting_states:
                return input_str  # Found!
            elif ic != '^':
                queue.append((ns, tuple(new_stack), input_str + ic))
```

### Gotcha
The challenge file had CRLF line endings, causing `\r` to be included in push strings.

## Key Techniques
- Pushdown Automaton (PDA) state machine analysis
- Bytecode parsing and interpretation
- BFS search for valid input string
- CRLF line ending handling
