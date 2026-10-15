package ghidra.emotionengine;

import java.util.Arrays;
import java.util.List;

import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.bin.format.elf.extend.MIPS_ElfExtension;
import ghidra.emotionengine.dvp.DvpOverlayTable;
// import ghidra.emotionengine.iop.IopModSection;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.classfinder.ExtensionPointProperties;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

@ExtensionPointProperties(priority = 2)
public class EE_ElfExtension extends MIPS_ElfExtension {

	public static final short ET_IRX = -128;
	public static final short ET_IRX2 = -127;
	public static final short ET_ERX2 = -111;

	public static final int E_MIPS_MACH_5900 = 0x00920000;

	// Program Headers
	public static final ElfProgramHeaderType PT_MIPS_IRXHDR = new ElfProgramHeaderType(0x70000080, "PT_MIPS_IRXHDR",
			"IRX header");

	private static final int SHT_MIPS_IOPMOD_VALUE = 0x70000080;
	private static final int SHT_DVP_OVERLAY_TABLE_VALUE = 0x7ffff420;

	// Sections Headers
	public static final ElfSectionHeaderType SHT_MIPS_IOPMOD = new ElfSectionHeaderType(SHT_MIPS_IOPMOD_VALUE,
			"SHT_MIPS_IOPMOD", "IOP Module Information");
	public static final ElfSectionHeaderType SHT_DVP_OVERLAY_TABLE = new ElfSectionHeaderType(
			SHT_DVP_OVERLAY_TABLE_VALUE, "SHT_DVP_OVERLAY_TABLE", "The VU overlay table");
	public static final ElfSectionHeaderType SHT_DVP_OVERLAY = new ElfSectionHeaderType(0x7ffff421, "SHT_DVP_OVERLAY",
			"A VU overlay");

	// OUT OF RANGE?
	// public static final ElfSectionHeaderType SHT_MW_CATS = new
	// ElfSectionHeaderType(
	// 0xca2a82c2, "SHT_MW_CATS", "Unknown Section from Metrowerks CATS Utility");

	public static final String SHNAME_DVP_OVERLAY_STRTAB = ".DVP.ovlystrtab";
	public static final String SHNAME_DVP_OVERLAY_TABLE = ".DVP.ovlytab";

	// DVP Values
	/* These values are used for the dvp. */
	public static final byte STO_DVP_DMA = (byte) 0xe8;
	public static final byte STO_DVP_VIF = (byte) 0xe9;
	public static final byte STO_DVP_GIF = (byte) 0xea;
	public static final byte STO_DVP_VU = (byte) 0xeb;
	/* Reserve a couple in case we need them. */
	public static final byte STO_DVP_RES1 = (byte) 0xec;
	public static final byte STO_DVP_RES2 = (byte) 0xed;

	@Override
	public String getDataTypeSuffix() {
		return "_EE";
	}

	@Override
	public boolean canHandle(ElfLoadHelper elfLoadHelper) {
		return EE_Util.isEmotionEngine(elfLoadHelper.getProgram());
	}

	@Override
	public void processElf(ElfLoadHelper helper, TaskMonitor monitor) throws CancelledException {

		super.processElf(helper, monitor);
		ElfHeader elf = helper.getElfHeader();
		// IRX/IOP ELF files also use this extension, but do not share
		// the Emotion Engine's RAM and BIOS mirror layout.
		if (EE_Util.isEmotionEngineCpu(helper.getProgram())) {
			try {
				createMirrorBlocks(helper);
			} catch (Exception e) {
				helper.log(e);
			}
		}
		for (ElfSectionHeader shdr : elf.getSections()) {
			monitor.checkCancelled();
			EE_ElfSection section;
			switch (shdr.getType()) {
			// TODO: Integrate from bigianb fork
			// case SHT_MIPS_IOPMOD_VALUE:
			// 	section = new IopModSection(shdr, helper);
			// 	break;
			// case SHT_DVP_OVERLAY_TABLE_VALUE:
			//	section = new DvpOverlayTable(shdr, helper);
			//	break;
			default:
				section = null;
				break;
			}
			try {
				if (section == null) {
					String name = shdr.getNameAsString();
					if (name != null) {
						if (name.equals("heap") && shdr.getSize() == 0) {
							createHeapSection(helper, shdr);
						}
					}
				}
				//} else {
				//	section.parse(monitor);
				//}
			} catch (Exception e) {
				helper.log(e);
			}
		}
	}

	private void createHeapSection(ElfLoadHelper helper, ElfSectionHeader shdr) throws Exception {
		Program program = helper.getProgram();
		List<Symbol> symbols = program.getSymbolTable().getSymbols("_gp", program.getGlobalNamespace());
		if (symbols.isEmpty()) {
			return;
		}
		Address endExclusive = helper.getDefaultAddress(shdr.getAddress());
		Address start = getMaxAddress(helper);
		if (start == null || endExclusive.compareTo(start) <= 0) {
			return; // Empty or invalid synthetic heap range
		}
		long size = endExclusive.subtract(start);
		Memory mem = program.getMemory();
		MemoryBlock block = mem.createUninitializedBlock("heap", start, size, false);
		block.setExecute(shdr.isExecutable());
		block.setRead(true);
		block.setWrite(true);
		ProgramModule root = program.getListing().getDefaultRootModule();
		if (root.getIndex("heap") == -1) {
			ProgramFragment frag = root.createFragment("heap");
			frag.move(start, endExclusive.subtract(1));
		}
	}

	private Address getMaxAddress(ElfLoadHelper helper) {
		Program program = helper.getProgram();
		return Arrays.stream(program.getMemory().getBlocks()).filter(MemoryBlock::isLoaded)
				.filter(MemoryBlock::isInitialized).map(MemoryBlock::getEnd).map(Address::next).max(Address::compareTo)
				.orElse(null);
	}

	/**
	 * Byte mapped EE aliases are optional conveniences, not mandatory ELF
	 * sections. In particular, a ROM-aware/synthetic ELF may already load the
	 * original bytes directly at 0xBFC00000. Never shadow or overwrite them.
	 *
	 * Treat each alias independently: one occupied range must not prevent
	 * unrelated RAM/BIOS aliases from being created.
	 */
	private static void createMirrorBlocks(ElfLoadHelper helper) {
		final long mainRamSize = 0x02000000L;
		final long acceleratedRamSize = 0x01F00000L;
		final long biosRomSize = 0x00400000L;

		Program program = helper.getProgram();
		Memory mem = program.getMemory();

		createOptionalMirror(helper, "RAM(uncached)", 0x20000000L,
			0x00000000L, mainRamSize, true);

		// 0x30100000 aliases physical RAM at 0x00100000.
		createOptionalMirror(helper, "RAM(uncached_and_accelerated)", 0x30100000L,
			0x00100000L, acceleratedRamSize, true);

		/*
		 * A conventional EE ELF uses a physical BIOS mapping at 0x1FC00000.
		 * The PS2 boot-flow ELF deliberately puts its authentic RESET/ROMDIR
		 * bytes in the execution alias at 0xBFC00000 instead. If that alias
		 * is the only initialized source, mirror the cached view from it,
		 * not from an empty physical region.
		 *
		 * Prefer a directly loaded, initialized block over a previously
		 * synthesized byte-mapped alias. The destination overlapping the
		 * source is harmless: createOptionalMirror will preserve the
		 * existing block rather than attempting a conflicting allocation.
		 */
		long romSource = 0x1FC00000L;
		if (!isDirectlyInitialized(mem, helper.getDefaultAddress(romSource)) &&
				isDirectlyInitialized(mem, helper.getDefaultAddress(0xBFC00000L))) {
			romSource = 0xBFC00000L;
			helper.log("EE BIOS: ROM bytes already loaded at 0xBFC00000; " +
				"using the imported bytes as the source for optional BIOS mirrors.");
		}

		createOptionalMirror(helper, "BIOS/rom09(cached)", 0x9FC00000L,
			romSource, biosRomSize, false);
		createOptionalMirror(helper, "BIOS/rom0b(uncached)", 0xBFC00000L,
			romSource, biosRomSize, false);
	}

	private static boolean isDirectlyInitialized(Memory mem, Address address) {
		MemoryBlock block = mem.getBlock(address);
		return block != null && block.isInitialized() && !block.isMapped();
	}

	/**
	 * Only the primary address space participates in the EE alias map.
	 * An overlap anywhere in the requested target interval is sufficient
	 * to preserve the imported memory, including partial overlaps.
	 */
	private static MemoryBlock findMirrorConflict(Memory mem, Address start, Address end) {
		for (MemoryBlock block : mem.getBlocks()) {
			if (!start.getAddressSpace().equals(block.getStart().getAddressSpace())) {
				continue;
			}
			if (block.getEnd().compareTo(start) >= 0 &&
					block.getStart().compareTo(end) <= 0) {
				return block;
			}
		}
		return null;
	}

	private static void createOptionalMirror(ElfLoadHelper helper, String name,
			long destinationOffset, long sourceOffset, long length, boolean writable) {
		Program program = helper.getProgram();
		Memory mem = program.getMemory();
		Address destination = helper.getDefaultAddress(destinationOffset);
		Address source = helper.getDefaultAddress(sourceOffset);
		Address end;
		try {
			end = destination.addNoWrap(length - 1);
		}
		catch (Exception e) {
			helper.log("EE alias " + name + ": invalid target range: " + e.getMessage());
			return;
		}

		MemoryBlock conflict = findMirrorConflict(mem, destination, end);
		if (conflict != null) {
			helper.log("EE alias " + name + " not created: existing block '" +
				conflict.getName() + "' overlaps target " + destination +
				".." + end + "; existing ELF memory preserved.");
			return;
		}

		try {
			MemoryBlock block = mem.createByteMappedBlock(name,
				destination, source, length, false);
			if (writable) {
				block.setWrite(true);
			}
		}
		catch (Exception e) {
			// A failed optional alias must never abort the ELF import or
			// prevent subsequent independent aliases from being attempted.
			helper.log("EE alias " + name + " not created: " + e.getMessage());
		}
	}
}
