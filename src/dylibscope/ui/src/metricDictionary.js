export const metricDictionary = {
  deployment_target: {
    label: 'Deployment target',
    group: 'High-level analysis',
    meaning: 'Minimum iOS version declared by the Mach-O binary, when available.',
    interpretation: 'Useful for compatibility context. It is not directly scored as an attack-surface metric.',
  },
  num_sections: {
    label: 'Number of sections',
    group: 'High-level analysis',
    meaning: 'Number of Mach-O sections found by LIEF.',
    interpretation: 'More sections can indicate a more complex binary layout. It contributes to the HLA score with the existing profile weight.',
  },
  num_symbols: {
    label: 'Number of symbols',
    group: 'High-level analysis',
    meaning: 'Total symbol count extracted from the Mach-O binary.',
    interpretation: 'A larger symbol surface can indicate a broader static interface or more implementation complexity. It is one of the strongest HLA contributors.',
  },
  imported_functions: {
    label: 'Imported functions',
    group: 'High-level analysis',
    meaning: 'List of external functions referenced by the library.',
    interpretation: 'Used as context. The count is used for scoring instead of the raw list.',
  },
  imported_function_count: {
    label: 'Imported function count',
    group: 'High-level analysis',
    meaning: 'Number of imported functions after splitting the import list.',
    interpretation: 'A larger import surface suggests more external dependencies and interaction points. It maps to the existing import-count profile metric.',
  },
  exported_functions: {
    label: 'Exported functions',
    group: 'High-level analysis',
    meaning: 'List of functions exported by the library, when available.',
    interpretation: 'Used as context. The current derived score keeps the existing HLA/LLA profile weights and does not directly weight this list.',
  },
  exported_function_count: {
    label: 'Exported function count',
    group: 'High-level analysis',
    meaning: 'Number of exported functions after splitting the export list.',
    interpretation: 'Useful for interface-size analysis. It is not currently part of the existing weighted profile score.',
  },
  cfg_edge_count: {
    label: 'CFG edge count',
    group: 'Low-level analysis',
    meaning: 'Number of control-flow graph edges extracted by the Ghidra pipeline.',
    interpretation: 'Higher values can indicate more complex control flow and larger implementation surface. This is a major LLA profile contributor.',
  },
  internal_function_count: {
    label: 'Internal function count',
    group: 'Low-level analysis',
    meaning: 'Number of internal functions found by Ghidra.',
    interpretation: 'Useful for implementation-size context. It is not directly weighted in the current derived score.',
  },
  internal_variable_count: {
    label: 'Internal variable count',
    group: 'Low-level analysis',
    meaning: 'Number of internal variables identified by the Ghidra analysis.',
    interpretation: 'Useful for complexity context. It is not directly weighted in the current derived score.',
  },
  allocation_call_count: {
    label: 'Allocation call count',
    group: 'Low-level analysis',
    meaning: 'Number of calls related to memory allocation patterns detected by Ghidra.',
    interpretation: 'Allocation-heavy code may require closer manual review. This contributes to the LLA profile score.',
  },
  syscall_function_count: {
    label: 'Syscall function count',
    group: 'Low-level analysis',
    meaning: 'Number of syscall-related functions detected by the low-level extractor.',
    interpretation: 'Syscall-adjacent code is security-relevant because it is closer to OS boundary interactions. This contributes to the LLA profile score.',
  },
  mach_port_function_count: {
    label: 'Mach port function count',
    group: 'Low-level analysis',
    meaning: 'Number of Mach-port-related functions detected by the low-level extractor.',
    interpretation: 'Mach ports are important IPC primitives in iOS. More Mach-port-related usage can suggest more IPC-facing behavior. This contributes to the LLA profile score.',
  },
};

export const scoreDictionary = {
  score: 'Weighted 0–100 static-complexity score derived from existing DylibScope HLA/LLA profile weights. It is heuristic.',
  band: 'Human-readable score bucket: low, medium, or high static complexity.',
  confidence: 'Coverage indicator based on how much of the expected weighted metric profile is available for that observation.',
  risk_points: 'Rule-based explanatory tags generated from high raw metric values or security-relevant metric presence.',
  top_contributors: 'Metrics that contributed most to the score after normalization and weighting.',
};
