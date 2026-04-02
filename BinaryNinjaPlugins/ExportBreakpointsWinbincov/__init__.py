import binaryninja
import csv
import os

def export_basic_block_breakpoints(bv):
    """
    Iterates through all functions and basic blocks in the current BinaryView
    and exports breakpoint information to a CSV file.
    """
    
    # Get the base address of the module
    base_addr = bv.start
    
    # Get the module name (e.g., "ntdll.dll") from the full file path
    module_name = os.path.basename(bv.file.filename)
    
    # Ask the user where to save the file (still .csv is fine, or .tsv)
    output_file = binaryninja.interaction.get_save_filename_input("Save Breakpoint Info", "tsv", f"{module_name}_breakpoints.tsv")
    
    if not output_file:
        binaryninja.log_info("Breakpoint export cancelled.")
        return

    # A list to hold all our breakpoint data
    breakpoint_data = []

    # Iterate over every function in the binary
    for func in bv.functions:
        func_name = func.name
        demangle_type, demangle_name = binaryninja.demangle_ms(bv.arch, func_name)

        if demangle_type is not None:
            func_name = "::".join(demangle_name)

        # Iterate over every basic block in the function
        for bb in func.basic_blocks:
            bb_start_offset = bb.start - base_addr
            bb_end_offset = bb.end - base_addr
            func_offset = bb.start - func.start
            
            # --- Set Breakpoint Type ---
            # You can customize this logic.
            # For this example, we'll set all basic blocks to FREQ.
            bp_type = "FREQ" 

            # Add the data for this basic block
            breakpoint_data.append([
                module_name,
                bb_start_offset,
                bp_type,
                func_name,
                func_offset,
                bb_start_offset, # address_range start
                bb_end_offset    # address_range end
            ])

    # Write all collected data to the TSV file
    try:
        # 4. Open with utf-8 encoding for safety
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            
            # --- THIS IS THE KEY CHANGE ---
            # 5. Use a Tab delimiter instead of a comma
            writer = csv.writer(f, delimiter='\t') 
            
            # Write the header
            writer.writerow([
                "module_name", 
                "offset", 
                "type", 
                "function_name", 
                "function_offset", 
                "range_start", 
                "range_end"
            ])
            
            # Write all the breakpoint rows
            writer.writerows(breakpoint_data)
            
        binaryninja.log_info(f"Successfully exported {len(breakpoint_data)} breakpoints to {output_file}")
        
    except Exception as e:
        binaryninja.log_error(f"Failed to write breakpoint file: {e}")


binaryninja.plugin.PluginCommand.register(
    "Export Breakpoints for winbincov",
    "Exports Breakpoints for winbincov",
    export_basic_block_breakpoints
)