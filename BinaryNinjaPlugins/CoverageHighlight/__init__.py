from binaryninja import HighlightStandardColor, log_info, log_warn, log_error
from binaryninja.interaction import get_open_filename_input
from binaryninja.plugin import PluginCommand
import os


def highlight_coverage(bv):
    """
    Reads a coverage file (format: ModuleName+Offset) and highlights
    the instructions in the current BinaryView.
    """
    
    # Get the base address of the currently loaded binary
    base_addr = bv.start
    
    # Ask the user to select the coverage file
    filepath = get_open_filename_input("Select Coverage File")
    
    if not filepath:
        log_info("Coverage import cancelled.")
        return

    highlight_count = 0
    skipped_count = 0

    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                parts = line.split('+')
                if len(parts) == 2:
                    try:
                        # Parse the offset (e.g., '19c0')
                        offset = int(parts[1], 16)
                        
                        # Calculate the absolute address
                        addr = base_addr + offset
                        
                        # Find the function(s) containing this address
                        funcs = bv.get_functions_containing(addr)
                        
                        if funcs:
                            # Use the first function found
                            func = funcs[0]
                            
                            # Set the highlight for the specific instruction
                            func.set_user_instr_highlight(
                                addr,
                                HighlightStandardColor.BlueHighlightColor
                            )
                            highlight_count += 1
                        else:
                            # Address is valid but not in a function
                            log_warn(f"Address 0x{addr:x} not in a function. Skipping.")
                            skipped_count += 1
                            
                    except ValueError:
                        log_warn(f"Skipping malformed line: {line}")
                        skipped_count += 1
                else:
                    log_warn(f"Skipping malformed line: {line}")
                    skipped_count += 1

    except Exception as e:
        log_error(f"Error reading file: {e}")
        return

    log_info(f"Successfully highlighted {highlight_count} instructions.")
    if skipped_count > 0:
        log_warn(f"Skipped {skipped_count} lines (malformed or address not found).")

def highlight_basic_blocks(bv):
    """
    Reads a coverage file (format: ModuleName+Offset) and highlights
    all instructions in the basic block for each address.
    """
    
    base_addr = bv.start
    filepath = get_open_filename_input("Select Coverage File")
    
    if not filepath:
        log_info("Coverage import cancelled.")
        return

    highlight_block_count = 0
    skipped_count = 0
    
    # Use a set to avoid re-highlighting the same block
    # if it's hit multiple times in the trace
    highlighted_blocks = set()

    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                parts = line.split('+')
                if len(parts) == 2:
                    try:
                        offset = int(parts[1], 16)
                        addr = base_addr + offset
                        funcs = bv.get_functions_containing(addr)
                        
                        if funcs:
                            func = funcs[0]
                            bb = func.get_basic_block_at(addr)
                            
                            if bb:
                                # Check if we've already highlighted this block
                                if bb.start in highlighted_blocks:
                                    continue
                                
                                # --- THIS IS THE MODIFIED PART ---
                                # Iterate over instructions in the basic block
                                # A basic block object iterates over (tokens, length) tuples
                                current_addr = bb.start
                                for (tokens, length) in bb:
                                    # Apply highlight to the instruction's address
                                    func.set_user_instr_highlight(
                                        current_addr,
                                        HighlightStandardColor.BlueHighlightColor
                                    )
                                    current_addr += length
                                # ---------------------------------
                                
                                highlighted_blocks.add(bb.start)
                                highlight_block_count += 1
                            else:
                                log_warn(f"Could not find basic block at 0x{addr:x}. Skipping.")
                                skipped_count += 1
                        else:
                            log_warn(f"Address 0x{addr:x} not in a function. Skipping.")
                            skipped_count += 1
                            
                    except ValueError:
                        log_warn(f"Skipping malformed line: {line}")
                        skipped_count += 1
                else:
                    log_warn(f"Skipping malformed line: {line}")
                    skipped_count += 1

    except Exception as e:
        log_error(f"Error reading file: {e}")
        return

    log_info(f"Successfully highlighted {highlight_block_count} basic blocks.")
    if skipped_count > 0:
        log_warn(f"Skipped {skipped_count} lines (malformed or address not found).")

def clear_coverage(bv):
    """
    Clears all instruction-based highlights from all functions
    by iterating over every instruction.
    """
    log_info("Clearing all user instruction highlights from all functions...")
    
    # We must iterate through every function
    for func in bv.functions:
        
        # And every basic block in that function
        for bb in func.basic_blocks:
            
            # And every instruction in that basic block
            current_addr = bb.start
            for (tokens, length) in bb:
                
                # Set the highlight to 'None'
                func.set_user_instr_highlight(
                    current_addr,
                    HighlightStandardColor.NoHighlightColor
                )
                current_addr += length
                
    log_info("Done.")

# Register the plugins
PluginCommand.register(
    "Coverage Highlights\\Import Coverage File (Basic Blocks)",
    "Highlights basic blocks from a module+offset coverage file.",
    highlight_basic_blocks
)
PluginCommand.register(
    "Coverage Highlights\\Import Coverage File (Instructions)",
    "Highlights instructions from a module+offset coverage file.",
    highlight_coverage
)
PluginCommand.register(
    "Coverage Highlights\\Clear Coverage Highlights",
    "Clears all instruction highlights from all functions.",
    clear_coverage
)