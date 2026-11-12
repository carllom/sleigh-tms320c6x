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
// Sets the decode context of TMS320C6000 header-based fetch packets (compact
// instructions) in the selection, or in all executable memory, and
// disassembles again any of those packets that had already been disassembled.
// The "TMS320C6x Fetch Packet Headers" analyzer does the same automatically
// before disassembly; use this after adding or changing code by hand.
//@category TMS320C6x

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.processors.tms320c6x.TMS320C6xFetchPackets;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;

public class C6xFetchPacketHeaders extends GhidraScript {

	@Override
	protected void run() throws Exception {
		if (!currentProgram.getLanguage()
				.getProcessor()
				.toString()
				.equals(TMS320C6xFetchPackets.PROCESSOR_NAME)) {
			printerr("Not a TMS320C6x program");
			return;
		}

		AddressSet set = new AddressSet();
		if (currentSelection != null && !currentSelection.isEmpty()) {
			set.add(currentSelection);
		}
		else {
			for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
				if (block.isExecute() && block.isInitialized()) {
					set.add(block.getStart(), block.getEnd());
				}
			}
		}

		// header-based packets that were disassembled without their context
		List<Address> redo = new ArrayList<>();
		AddressSet clear = new AddressSet();
		for (AddressRange range : set) {
			long first = range.getMinAddress().getOffset() & ~31L;
			for (long fp = first; fp <= range.getMaxAddress().getOffset(); fp += 32) {
				monitor.checkCancelled();
				Address start = range.getMinAddress().getNewAddress(fp);
				int header;
				try {
					header = currentProgram.getMemory()
							.getInt(start.add(TMS320C6xFetchPackets.HEADER_OFFSET));
				}
				catch (MemoryAccessException | AddressOutOfBoundsException e) {
					continue;
				}
				if (!TMS320C6xFetchPackets.isHeader(header)) {
					continue;
				}
				AddressSet packet = new AddressSet(start, start.add(31));
				InstructionIterator it = currentProgram.getListing().getInstructions(packet, true);
				if (it.hasNext()) {
					Instruction first32 = it.next();
					redo.add(first32.getAddress());
					clear.add(packet);
				}
			}
		}
		if (!clear.isEmpty()) {
			clearListing(clear);
		}

		int count = TMS320C6xFetchPackets.applyHeaderContext(currentProgram, set, monitor);

		for (Address a : redo) {
			monitor.checkCancelled();
			if (currentProgram.getListing().getInstructionAt(a) == null) {
				new DisassembleCommand(a, null, true).applyTo(currentProgram, monitor);
			}
		}
		println(count + " header-based fetch packets, " + redo.size() + " disassembled again");
	}
}
