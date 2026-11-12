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
package ghidra.app.plugin.processors.tms320c6x;

import ghidra.program.model.lang.ParallelInstructionLanguageHelper;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * Marks TMS320C6000 instructions that execute in parallel with the previous
 * instruction with "||", as TI's disassembler does.
 */
public class TMS320C6xParallelInstructionHelper implements ParallelInstructionLanguageHelper {

	public TMS320C6xParallelInstructionHelper() {
	}

	private static boolean isHeaderWord(Instruction instr) {
		return instr.getMnemonicString().equals(".fphead");
	}

	@Override
	public String getMnemonicPrefix(Instruction instr) {
		return isParallelInstruction(instr) ? "||" : null;
	}

	@Override
	public boolean isParallelInstruction(Instruction instr) {
		if (isHeaderWord(instr)) {
			return false;
		}
		try {
			return TMS320C6xFetchPackets.previousPBit(instr.getProgram().getMemory(),
				instr.getAddress());
		}
		catch (MemoryAccessException e) {
			return false;
		}
	}

	@Override
	public boolean isEndOfParallelInstructionGroup(Instruction instr) {
		if (isHeaderWord(instr)) {
			return true;
		}
		try {
			return !TMS320C6xFetchPackets.pBit(instr.getProgram().getMemory(), instr.getAddress());
		}
		catch (MemoryAccessException e) {
			return true;
		}
	}
}
