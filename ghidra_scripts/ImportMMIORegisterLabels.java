// Create a label for each MMIO register in a namespace called "registers".
//@category ghidra-emotionengine

import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

public class ImportMMIORegisterLabels extends GhidraScript {

    public void run() throws Exception {
        Namespace registerNamespace = getNamespace(null, "registers");
        if(registerNamespace == null) {
            registerNamespace = currentProgram.getSymbolTable().createNameSpace(
                currentProgram.getGlobalNamespace(),
                "registers",
                SourceType.USER_DEFINED
            );
        }
        
        // The register names are the language's default symbols (r5900.pspec): move them into the
        // "registers" namespace (Ghidra-Rare: they used to be SLEIGH symbols in the ram space, which
        // stopped reference creation, upstream issue #93).
        for(ghidra.program.model.lang.AddressLabelInfo info : currentProgram.getLanguage().getDefaultSymbols()) {
            monitor.checkCancelled();
            Address address = info.getAddress();
            if(address.getOffset() < 0x10000000L || address.getOffset() >= 0x12002000L) {
                continue;
            }
            Symbol[] oldSymbols = currentProgram.getSymbolTable().getSymbols(address);
            for(Symbol symbol : oldSymbols) {
                symbol.delete();
            }
            currentProgram.getSymbolTable().createLabel(
                address,
                info.getLabel(),
                registerNamespace,
                SourceType.USER_DEFINED
            );
        }
    }

}
