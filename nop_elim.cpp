// Step 1: Build label-to-index mapping for original bytecode
std::unordered_map<int, size_t> buildLabelMap(const vector<BCInstruction> &instructions) {
    std::unordered_map<int, size_t> labelMap;
    
    for (size_t i = 0; i < instructions.size(); ++i) {
        const auto &inst = instructions[i];
        if (inst.isLabel && inst.bc == OP_nop) {
            labelMap[inst.label] = i;
        }
    }
    
    return labelMap;
}

// Step 2: Find which labels are actually referenced
std::set<int> findReferencedLabels(const vector<BCInstruction> &instructions) {
    std::set<int> referenced;
    
    for (const auto &inst : instructions) {
        if (inst.bc == OP_goto || inst.bc == OP_catch || inst.bc == OP_gosub ||
            inst.bc == OP_if_true || inst.bc == OP_if_false ||
            inst.bc == OP_if_true8 || inst.bc == OP_if_false8) {
            
            // The data.four contains the label ID (before patching)
            // or the offset (after patching) - we need to reverse engineer this
            
            // If patchGotos was already called, we need to find the label differently
            // For now, let's assume we call this before patchGotos
            referenced.insert(inst.data.four);
        }
    }
    
    return referenced;
}

// Step 3: Create optimized instruction list
vector<BCInstruction> eliminateUnnecessaryNOPs(const vector<BCInstruction> &original) {
    auto labelMap = buildLabelMap(original);
    auto referencedLabels = findReferencedLabels(original);
    
    vector<BCInstruction> optimized;
    
    for (size_t i = 0; i < original.size(); ++i) {
        const auto &inst = original[i];
        
        if (inst.bc == OP_nop) {
            if (inst.isLabel) {
                // Only keep labels that are actually referenced
                if (referencedLabels.count(inst.label) > 0) {
                    optimized.push_back(inst);
                }
                // Skip unreferenced labels
            } else {
                // Skip standalone NOPs (padding NOPs)
                continue;
            }
        } else {
            // Keep all non-NOP instructions
            optimized.push_back(inst);
        }
    }
    
    return optimized;
}

// Step 4: Safe offset calculation using byte positions
int findOffsetSafe(const vector<BCInstruction> &instructions, int targetLabel) {
    int currentOffset = 0;
    
    for (const auto &inst : instructions) {
        if (inst.isLabel && inst.bc == OP_nop && inst.label == targetLabel) {
            return currentOffset;
        }
        
        // Only count non-label NOPs and other instructions toward offset
        if (!(inst.bc == OP_nop && inst.isLabel)) {
            currentOffset += short_opcode_info(inst.bc).size;
        }
    }
    
    // Label not found - this shouldn't happen with proper code
    fprintf(stderr, "Warning: Label %d not found\n", targetLabel);
    return 0;
}

// Step 5: Updated patching function
void patchGotosOptimized(vector<BCInstruction> &instructions) {
    int currOffset = 0;
    
    for (size_t i = 0; i < instructions.size(); ++i) {
        auto &inst = instructions[i];
        
        if (inst.bc == OP_goto || inst.bc == OP_catch || inst.bc == OP_gosub) {
            uint32_t targetLabel = inst.data.four;
            int actualOffset = findOffsetSafe(instructions, targetLabel);
            inst.data.four = actualOffset - currOffset;
        }
        else if (inst.bc == OP_if_true || inst.bc == OP_if_true8) {
            uint32_t targetLabel = inst.data.four;
            int actualOffset = findOffsetSafe(instructions, targetLabel);
            inst.data.four = actualOffset - currOffset;
        }
        else if (inst.bc == OP_if_false || inst.bc == OP_if_false8) {
            uint32_t targetLabel = inst.data.four;
            int actualOffset = findOffsetSafe(instructions, targetLabel);
            inst.data.four = actualOffset - currOffset;
        }
        
        // Only advance offset for non-label instructions
        if (!(inst.bc == OP_nop && inst.isLabel)) {
            currOffset += short_opcode_info(inst.bc).size;
        }
    }
}

// Step 6: Main optimization function to integrate into generateBytecode
vector<BCInstruction> optimizeBytecode(vector<BCInstruction> &instructions) {
    // IMPORTANT: Do this BEFORE calling patchGotos for the first time
    // because we need the original label IDs, not the patched offsets
    
    auto optimized = eliminateUnnecessaryNOPs(instructions);
    
    // Now patch the gotos with correct offsets
    patchGotosOptimized(optimized);
    
    return optimized;
}

// Step 7: Integration into your generateBytecode function
JSValue generateBytecodeOptimized(JSContext *ctx, IridiumSEXP *node) {
    
    vector<BCInstruction> instructions;
    
    // Don't add the initial padding NOP anymore
    // BCInstruction inst;
    // inst.bc = 0;
    // instructions.push_back(inst);
    
    for (int idx = 0; idx < bbList->numArgs; idx++) {
        IridiumSEXP *bb = bbList->args[idx];
        ensureTag(bb, "BB");
        pushLabel(ctx, instructions, getFlagNumber(bb, "IDX"));
        
        for (int stmtIDX = 0; stmtIDX < bb->numArgs; stmtIDX++) {
            IridiumSEXP *currStmt = bb->args[stmtIDX];
            handleIriStmt(ctx, instructions, currStmt);
        }
    }
    
    // CRITICAL: Optimize BEFORE patching
    instructions = optimizeBytecode(instructions);
    
    // Don't call the original patchGotos - it's handled in optimizeBytecode
    // patchGotos(instructions);
    
    JSValue res = generateQjsFunction(ctx, bbContainer, instructions);
    
}

// Alternative: If you want to keep the original generateBytecode structure,
// add this right after instruction generation but before patchGotos:
void addOptimizationToExistingCode() {
    // In your existing generateBytecode function, replace:
    //   patchGotos(instructions);
    // With:
    //   instructions = optimizeBytecode(instructions);
}