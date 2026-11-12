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

import java.math.BigInteger;
import java.util.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * TMS320C6000 fetch packets.
 * <p>
 * Code is fetched in 32-byte aligned fetch packets. In a header-based packet
 * (C64x+ and later) the last word is a header with 0xE in bits 31-28 that says
 * which words hold pairs of 16-bit compact instructions, gives the p-bits of
 * the compact instructions and some options for decoding them. Sleigh cannot
 * read ahead to the header, so its fields are copied into context registers
 * over the whole packet before the packet is disassembled.
 */
public final class TMS320C6xFetchPackets {

	public static final String PROCESSOR_NAME = "TMS320C6x";

	public static final int PACKET_SIZE = 32;
	public static final int HEADER_OFFSET = 28;

	/** Context fields set from the header, see tms320c6x.sinc */
	private static final String[] HEADER_FIELDS =
		{ "fph", "layout", "hpbits", "prot", "rs", "dsz", "br", "sat" };

	private TMS320C6xFetchPackets() {
	}

	public static boolean isHeader(int word) {
		return (word >>> 28) == 0xe;
	}

	/** Bit n set if word n of the packet holds two compact instructions */
	public static int layout(int header) {
		return (header >>> 21) & 0x7f;
	}

	/**
	 * Get the p-bit of the instruction at the given address, which must be the
	 * start of an instruction.
	 * @param memory program memory
	 * @param addr instruction address
	 * @return true if the next instruction executes in parallel
	 * @throws MemoryAccessException if the packet can't be read
	 */
	public static boolean pBit(Memory memory, Address addr) throws MemoryAccessException {
		long offset = addr.getOffset();
		Address fp = addr.getNewAddress(offset & ~(PACKET_SIZE - 1));
		int pos = (int) (offset & (PACKET_SIZE - 1));
		int header = memory.getInt(fp.add(HEADER_OFFSET));
		if (isHeader(header)) {
			if (pos == HEADER_OFFSET) {
				return false;
			}
			int word = pos >> 2;
			if (((layout(header) >> word) & 1) != 0) {
				return ((header >> (pos >> 1)) & 1) != 0;
			}
		}
		return (memory.getInt(addr.getNewAddress(offset & ~3L)) & 1) != 0;
	}

	/**
	 * Find whether the instruction at the given address executes in parallel
	 * with the one before it, that is, the previous instruction's p-bit is set.
	 * @param memory program memory
	 * @param addr instruction address
	 * @return true if the instruction is not the first of its execute packet
	 * @throws MemoryAccessException if the packets can't be read
	 */
	public static boolean previousPBit(Memory memory, Address addr) throws MemoryAccessException {
		long offset = addr.getOffset();
		long fp = offset & ~(PACKET_SIZE - 1);
		int pos = (int) (offset & (PACKET_SIZE - 1));
		int header = memory.getInt(addr.getNewAddress(fp + HEADER_OFFSET));

		if (pos == 0) {
			// last instruction of the previous fetch packet
			if (fp < PACKET_SIZE) {
				return false;
			}
			long prev = fp - PACKET_SIZE;
			int prevHeader = memory.getInt(addr.getNewAddress(prev + HEADER_OFFSET));
			if (!isHeader(prevHeader)) {
				return (prevHeader & 1) != 0;
			}
			if (((layout(prevHeader) >> 6) & 1) != 0) {
				return ((prevHeader >> 13) & 1) != 0;
			}
			return (memory.getInt(addr.getNewAddress(prev + 24)) & 1) != 0;
		}

		if (!isHeader(header)) {
			return (memory.getInt(addr.getNewAddress(offset - 4)) & 1) != 0;
		}
		if (pos == HEADER_OFFSET) {
			return false;
		}
		int word = pos >> 2;
		boolean compact = ((layout(header) >> word) & 1) != 0;
		if (compact && (pos & 2) != 0) {
			return ((header >> (word * 2)) & 1) != 0;
		}
		if (word == 0) {
			return false;
		}
		if (((layout(header) >> (word - 1)) & 1) != 0) {
			return ((header >> ((word - 1) * 2 + 1)) & 1) != 0;
		}
		return (memory.getInt(addr.getNewAddress(fp + (word - 1) * 4)) & 1) != 0;
	}

	/**
	 * Set the header context of every header-based fetch packet that starts in
	 * the given set of addresses, and clear it from the other packets.
	 * Packets that already hold instructions are skipped.
	 * @param program the program
	 * @param set addresses to process; only initialized blocks are looked at
	 * @param monitor task monitor
	 * @return number of header-based packets found
	 * @throws CancelledException if cancelled
	 */
	public static int applyHeaderContext(Program program, AddressSetView set, TaskMonitor monitor)
			throws CancelledException {
		ProgramContext ctx = program.getProgramContext();
		Register base = ctx.getBaseContextRegister();
		Register[] fields = new Register[HEADER_FIELDS.length];
		for (int i = 0; i < fields.length; i++) {
			fields[i] = program.getRegister(HEADER_FIELDS[i]);
			if (fields[i] == null) {
				throw new IllegalStateException("Not a TMS320C6x language: no " + HEADER_FIELDS[i]);
			}
		}

		Memory memory = program.getMemory();
		Listing listing = program.getListing();
		int count = 0;
		for (MemoryBlock block : memory.getBlocks()) {
			if (!block.isInitialized() || !set.intersects(block.getStart(), block.getEnd())) {
				continue;
			}
			AddressSetView todo = set.intersect(new AddressSet(block.getStart(), block.getEnd()));
			for (AddressRange range : todo) {
				long first = range.getMinAddress().getOffset() & ~(PACKET_SIZE - 1L);
				long last = range.getMaxAddress().getOffset();
				monitor.initialize(last - first);
				for (long fp = first; fp <= last; fp += PACKET_SIZE) {
					monitor.checkCancelled();
					monitor.setProgress(fp - first);
					Address start = range.getMinAddress().getNewAddress(fp);
					Address end = start.add(PACKET_SIZE - 1);
					if (start.compareTo(block.getStart()) < 0) {
						start = block.getStart();
					}
					if (end.compareTo(block.getEnd()) > 0) {
						end = block.getEnd();
					}
					if (listing.getInstructions(new AddressSet(start, end), true).hasNext()) {
						continue;
					}
					int header;
					try {
						header = memory.getInt(start.getNewAddress(fp + HEADER_OFFSET));
					}
					catch (MemoryAccessException | AddressOutOfBoundsException e) {
						continue;
					}
					try {
						for (Register f : fields) {
							ctx.remove(start, end, f);
						}
						if (isHeader(header)) {
							RegisterValue v = new RegisterValue(base);
							v = v.assign(fields[0], BigInteger.ONE);
							v = v.assign(fields[1], BigInteger.valueOf(layout(header)));
							v = v.assign(fields[2], BigInteger.valueOf(header & 0x3fff));
							v = v.assign(fields[3], BigInteger.valueOf((header >> 20) & 1));
							v = v.assign(fields[4], BigInteger.valueOf((header >> 19) & 1));
							v = v.assign(fields[5], BigInteger.valueOf((header >> 16) & 7));
							v = v.assign(fields[6], BigInteger.valueOf((header >> 15) & 1));
							v = v.assign(fields[7], BigInteger.valueOf((header >> 14) & 1));
							ctx.setRegisterValue(start, end, v);
							count++;
						}
					}
					catch (ContextChangeException e) {
						// instructions were created meanwhile; leave the packet alone
					}
				}
			}
		}
		return count;
	}

	/**
	 * Find header-based fetch packets holding the given instructions whose
	 * header context has been lost, for example because code was cleared with
	 * its context and disassembled again, and disassemble them again with the
	 * context restored.
	 * @param program the program
	 * @param set addresses of new instructions
	 * @param repairs how often each packet was repaired so far, updated
	 * @param monitor task monitor
	 * @return number of packets repaired
	 * @throws CancelledException if cancelled
	 */
	public static int repairHeaderContext(Program program, AddressSetView set,
			Map<Long, Integer> repairs, TaskMonitor monitor) throws CancelledException {
		Register fph = program.getRegister(HEADER_FIELDS[0]);
		ProgramContext ctx = program.getProgramContext();
		Memory memory = program.getMemory();
		Listing listing = program.getListing();

		Set<Long> seen = new HashSet<>();
		List<Address> bad = new ArrayList<>();
		Map<Address, List<Address>> entries = new HashMap<>();
		for (Instruction ins : listing.getInstructions(set, true)) {
			monitor.checkCancelled();
			List<Address> targets = new ArrayList<>();
			targets.add(ins.getAddress());
			if (ins.getFallThrough() != null) {
				targets.add(ins.getFallThrough());
			}
			targets.addAll(Arrays.asList(ins.getFlows()));
			for (Address a : targets) {
				long fp = a.getOffset() & ~(PACKET_SIZE - 1L);
				BigInteger v = ctx.getValue(fph, a, false);
				if (v != null && v.signum() != 0) {
					continue;
				}
				Address fpa = a.getNewAddress(fp);
				if (!seen.add(fp)) {
					if (entries.containsKey(fpa)) {
						entries.get(fpa).add(a);
					}
					continue;
				}
				try {
					if (isHeader(memory.getInt(a.getNewAddress(fp + HEADER_OFFSET)))) {
						bad.add(fpa);
						entries.put(fpa, new ArrayList<>(List.of(a)));
					}
				}
				catch (MemoryAccessException | AddressOutOfBoundsException e) {
					// not a whole packet
				}
			}
		}

		int count = 0;
		for (Address fp : bad) {
			monitor.checkCancelled();
			MemoryBlock block = memory.getBlock(fp);
			if (block == null) {
				continue;
			}
			if (repairs.merge(fp.getOffset(), 1, Integer::sum) > MAX_REPAIRS) {
				continue;
			}
			count++;
			Address end = fp.add(PACKET_SIZE - 1);
			if (end.compareTo(block.getEnd()) > 0) {
				end = block.getEnd();
			}
			AddressSet packet = new AddressSet(fp, end);
			Deque<Address> todo = new ArrayDeque<>(entries.get(fp));
			Map<Address, InstructionOverrides> overrides = new HashMap<>();
			for (Instruction ins : listing.getInstructions(packet, true)) {
				todo.add(ins.getAddress());
				InstructionOverrides o = InstructionOverrides.of(ins);
				if (o != null) {
					overrides.put(ins.getAddress(), o);
				}
			}
			program.getBookmarkManager()
					.removeBookmarks(packet, BookmarkType.ERROR, "Bad Instruction", monitor);
			Instruction last = listing.getInstructionContaining(end);
			if (last != null && last.getMaxAddress().compareTo(end) > 0) {
				end = last.getMaxAddress();
			}
			listing.clearCodeUnits(fp, end, false);
			applyHeaderContext(program, packet, monitor);

			// Follow the flow within the packet one instruction at a time, so
			// that the overrides analysis put on the old instructions (calls to
			// functions that do not return) are back in place before their
			// flow is followed; otherwise the code that analysis cleared after
			// such a call comes back and is cleared again, over and over.
			AddressSet outside = new AddressSet();
			while (!todo.isEmpty()) {
				monitor.checkCancelled();
				Address a = todo.pop();
				if (!packet.contains(a) || listing.getInstructionAt(a) != null) {
					continue;
				}
				new DisassembleCommand(a, packet, false).applyTo(program, monitor);
				Instruction ins = listing.getInstructionAt(a);
				if (ins == null) {
					continue;
				}
				InstructionOverrides o = overrides.get(a);
				if (o != null) {
					o.restore(ins);
				}
				List<Address> next = new ArrayList<>(Arrays.asList(ins.getFlows()));
				if (ins.getFallThrough() != null) {
					next.add(ins.getFallThrough());
				}
				for (Address n : next) {
					if (packet.contains(n)) {
						todo.push(n);
					}
					else if (listing.getCodeUnitAt(n) instanceof Data d && !d.isDefined()) {
						outside.add(n);
					}
				}
			}
			// flows out of the packet into code that is not there yet are followed as usual
			if (!outside.isEmpty()) {
				new DisassembleCommand(outside, null, true).applyTo(program, monitor);
			}
		}
		return count;
	}

	/** How often a packet is repaired at most, in case analysis keeps undoing the repair */
	private static final int MAX_REPAIRS = 3;

	/** Overrides that analysis put on an instruction, kept across disassembling it again */
	private record InstructionOverrides(String mnemonic, int length, FlowOverride flow,
			Address fallThrough) {

		static InstructionOverrides of(Instruction ins) {
			FlowOverride flow = ins.getFlowOverride();
			boolean ft = ins.isFallThroughOverridden();
			if (flow == FlowOverride.NONE && !ft) {
				return null;
			}
			return new InstructionOverrides(ins.getMnemonicString(), ins.getLength(), flow,
				ft ? ins.getFallThrough() : NO_FALLTHROUGH);
		}

		/** Put the overrides back if the instruction still decodes the same */
		void restore(Instruction ins) {
			if (!ins.getMnemonicString().equals(mnemonic) || ins.getLength() != length) {
				return;
			}
			if (flow != FlowOverride.NONE) {
				ins.setFlowOverride(flow);
			}
			if (fallThrough != NO_FALLTHROUGH) {
				ins.setFallThrough(fallThrough);
			}
		}
	}

	/** Marks a fall-through that is not overridden; null is an overridden "no fall-through" */
	private static final Address NO_FALLTHROUGH = Address.NO_ADDRESS;

	/** __c6xabi_push_rts and __c6xabi_pop_rts as in TI's run-time library, one fetch packet each */
	private static final int[] PUSH_RTS = { 0x073c54f6, 0x000c1363, 0x96778777, 0x95778677,
		0x91778577, 0x00000000, 0x00000000, 0xe3800000 };
	private static final int[] POP_RTS = { 0xc577d177, 0xc677d577, 0x01efd677, 0x7777c777,
		0x00006000, 0x00000000, 0x00000000, 0xe1e00020 };

	public static final String PUSH_RTS_NAME = "__c6xabi_push_rts";
	public static final String POP_RTS_NAME = "__c6xabi_pop_rts";

	/**
	 * Find TI's register save and restore helpers, which are called with CALLP
	 * and return through A3 (push) or pop the caller's frame and return for it
	 * (pop), and create functions for them so that the cspec call-fixups apply
	 * and calls to pop_rts end the caller's flow.
	 * @param program the program
	 * @param set addresses to look in
	 * @param monitor task monitor
	 * @return number of helpers found
	 * @throws CancelledException if cancelled
	 */
	public static int markRuntimeHelpers(Program program, AddressSetView set, TaskMonitor monitor)
			throws CancelledException {
		Memory memory = program.getMemory();
		int count = 0;
		for (AddressRange range : set) {
			long first = (range.getMinAddress().getOffset() + PACKET_SIZE - 1) & ~(PACKET_SIZE - 1L);
			for (long fp = first; fp + PACKET_SIZE - 1 <= range.getMaxAddress().getOffset(); fp += PACKET_SIZE) {
				monitor.checkCancelled();
				Address a = range.getMinAddress().getNewAddress(fp);
				int[] w = new int[8];
				try {
					for (int i = 0; i < 8; i++) {
						w[i] = memory.getInt(a.add(i * 4));
					}
				}
				catch (MemoryAccessException e) {
					continue;
				}
				String name = Arrays.equals(w, PUSH_RTS) ? PUSH_RTS_NAME
						: Arrays.equals(w, POP_RTS) ? POP_RTS_NAME : null;
				if (name == null) {
					continue;
				}
				count++;
				try {
					Function f = program.getFunctionManager().getFunctionAt(a);
					if (f == null) {
						f = program.getFunctionManager()
								.createFunction(name, a, new AddressSet(a, a.add(PACKET_SIZE - 1)),
									SourceType.ANALYSIS);
					}
					else if (f.getSymbol().getSource() == SourceType.DEFAULT) {
						f.setName(name, SourceType.ANALYSIS);
					}
					if (name == POP_RTS_NAME) {
						f.setNoReturn(true);
					}
					f.setCallFixup(name);
				}
				catch (InvalidInputException | OverlappingFunctionException |
						DuplicateNameException e) {
					// leave it to the user
				}
			}
		}
		return count;
	}
}
