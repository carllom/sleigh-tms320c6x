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

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Sets the decode context of TMS320C6000 header-based fetch packets before
 * anything is disassembled, so that compact instructions decode correctly.
 */
public class TMS320C6xFetchPacketAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "TMS320C6x Fetch Packet Headers";
	private static final String DESCRIPTION =
		"Finds header-based fetch packets in executable memory and sets the context that " +
			"decodes their 16-bit compact instructions, and names the run-time library's " +
			"register save/restore helpers. Runs before disassembly.";

	public TMS320C6xFetchPacketAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.before());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage()
				.getProcessor()
				.toString()
				.equals(TMS320C6xFetchPackets.PROCESSOR_NAME);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		AddressSet code = new AddressSet();
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (block.isExecute() && block.isInitialized()) {
				code.add(block.getStart(), block.getEnd());
			}
		}
		code = code.intersect(set);
		if (code.isEmpty()) {
			return false;
		}
		monitor.setMessage("TMS320C6x fetch packet headers");
		int count = TMS320C6xFetchPackets.applyHeaderContext(program, code, monitor);
		log.appendMsg(NAME + ": " + count + " header-based fetch packets");
		TMS320C6xFetchPackets.markRuntimeHelpers(program, code, monitor);
		return true;
	}
}
