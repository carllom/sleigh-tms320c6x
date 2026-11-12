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

import java.util.*;

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Restores the header context of TMS320C6000 fetch packets that lost it.
 * <p>
 * Clearing code with its context (for example when analysis repairs the flow
 * after a call to a function that does not return) also removes the context
 * that the fetch packet analyzer set, so code disassembled there afterwards
 * decodes compact instructions as 32-bit ones. This puts the context back and
 * disassembles such packets again.
 */
public class TMS320C6xFetchPacketRepairAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "TMS320C6x Fetch Packet Repair";
	private static final String DESCRIPTION =
		"Disassembles again header-based fetch packets whose header context was cleared " +
			"together with code, so that their compact instructions decode correctly.";

	public TMS320C6xFetchPacketRepairAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.DISASSEMBLY.before());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage()
				.getProcessor()
				.toString()
				.equals(TMS320C6xFetchPackets.PROCESSOR_NAME);
	}

	/** How often each fetch packet was repaired, per program */
	private final Map<Program, Map<Long, Integer>> repairs = new WeakHashMap<>();

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Map<Long, Integer> counts = repairs.computeIfAbsent(program, p -> new HashMap<>());
		int n = TMS320C6xFetchPackets.repairHeaderContext(program, set, counts, monitor);
		if (n > 0) {
			log.appendMsg(NAME + ": " + n + " fetch packets disassembled again");
		}
		return true;
	}
}
