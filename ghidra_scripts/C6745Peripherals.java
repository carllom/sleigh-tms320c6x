/* ###
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Adds an uninitialized, volatile memory block over the TMS320C6745/C6747
// peripheral space (0x01800000-0x01f0afff, SPRS377F table 3-4), so that the
// decompiler treats register accesses as volatile, and creates the
// peripheral labels of the language if they are missing.
// Run it after auto-analysis: with the block in place during analysis, the
// many instruction words that are also peripheral addresses are taken for
// pointers and code is turned into data.
//@category TMS320C6x

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.AddressLabelInfo;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;

public class C6745Peripherals extends GhidraScript {

	private static final String BLOCK_NAME = "PERIPHERALS";
	private static final long START = 0x01800000L;
	private static final long LENGTH = 0x70b000L;

	@Override
	protected void run() throws Exception {
		Memory memory = currentProgram.getMemory();
		Address start = toAddr(START);
		Address end = start.add(LENGTH - 1);

		MemoryBlock existing = memory.getBlock(BLOCK_NAME);
		if (existing != null) {
			println(BLOCK_NAME + " already exists at " + existing.getStart());
		}
		else if (memory.intersects(start, end)) {
			printerr("Memory at " + start + "-" + end + " is already in use; no block added");
			return;
		}
		else {
			MemoryBlock block =
				memory.createUninitializedBlock(BLOCK_NAME, start, LENGTH, false);
			block.setPermissions(true, true, false);
			block.setVolatile(true);
			block.setComment("TMS320C6745/C6747 peripherals, SPRS377F table 3-4");
			println("Added " + BLOCK_NAME + " " + start + "-" + end);
		}

		SymbolTable symbols = currentProgram.getSymbolTable();
		int added = 0;
		for (AddressLabelInfo info : currentProgram.getLanguage().getDefaultSymbols()) {
			Address a = info.getAddress();
			if (a.getOffset() < START || a.getOffset() > end.getOffset()) {
				continue;
			}
			if (symbols.getGlobalSymbols(info.getLabel()).isEmpty()) {
				symbols.createLabel(a, info.getLabel(), SourceType.IMPORTED);
				added++;
			}
		}
		if (added > 0) {
			println("Added " + added + " peripheral labels");
		}
	}
}
