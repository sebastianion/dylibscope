import os, json
from ghidra.program.model.symbol import RefType
from ghidra.program.model.block import BasicBlockModel

from java.nio.file import Paths, StandardOpenOption, Files
from java.nio.channels import FileChannel
from java.nio import ByteBuffer


VERSION_TAGS = set([
    "iPhone1,1_1.0.2_1C28",
    "iPhone11,8_12.0_16A366",
    "iPhone_4.0_64bit_10.0.1_14A403",
    "iPhone_4.0_64bit_10.1_14B72",
    "iPhone_4.0_64bit_10.2_14C92",
    "iPhone_4.0_64bit_10.3.3_14G60",
    "iPhone_4.0_64bit_10.3_14E277",
    "iPhone_4.0_64bit_11.1.2_15B202",
    "iPhone_4.0_64bit_11.2.5_15D60",
    "iPhone5,1_6.0_10A405",
    "iPhone5,1_7.0_11A465",
    "iPhone5,1_8.0_12A365",
    "iPhone5,1_8.1_12B411",
    "iPhone5,1_8.3_12F70",
    "iPhone5,1_8.4_12H143",
    "iPhone5,1_9.0_13A344",
    "iPhone5,1_9.1_13B143",
    "iPhone5,1_9.2_13C75",
    "iPhone5,1_9.3_13E237",
    "iPhone6,2_11.0.0_15A372",
])

args = getScriptArgs()
outpath = args[0] if len(args) >= 1 else os.path.join(os.getcwd(), "ghidra_library_metrics.jsonl")
outpath = str(outpath)

program = currentProgram
if program is None:
    print("[!] No currentProgram; nothing to do.")
    exit(0)

fm = program.getFunctionManager()
listing = program.getListing()
binary_name = program.getName()
bbm = BasicBlockModel(program)

ALLOC_KEYWORDS = (
    "malloc", "calloc", "realloc", "valloc", "pvalloc",
    "memalign", "posix_memalign", "aligned_alloc",
    "malloc_zone_malloc", "malloc_zone_calloc", "malloc_zone_realloc",
)
ALLOC_EXCLUDE = ("free", "dealloc", "destroy")


def get_exec_path(prog):
    try:
        p = prog.getExecutablePath()
        if p:
            return str(p)
    except:
        pass
    try:
        df = prog.getDomainFile()
        if df:
            return str(df.getPathname())
    except:
        pass
    return prog.getName()


def basename(p):
    return os.path.basename(p) if p else program.getName()


full_path = get_exec_path(program)
file_name = basename(full_path)


def find_ios_tag(path):
    comps = [c for c in path.replace("\\", "/").split("/") if c]
    for c in comps:
        c = c[:-6]
        if c in VERSION_TAGS:
            return c
    return None


ios_version = find_ios_tag(full_path)


def is_internal_function(func):
    try:
        if func.isExternal():
            return False
    except:
        pass
    try:
        body = func.getBody()
        return body is not None and not body.isEmpty()
    except:
        return False

def count_cfg_edges(func):
    edges = 0
    it = bbm.getCodeBlocksContaining(func.getBody(), getMonitor())
    while it.hasNext() and not getMonitor().isCancelled():
        block = it.next()
        try:
            dests = block.getDestinations(getMonitor())
            while dests.hasNext() and not getMonitor().isCancelled():
                _ = dests.next()
                edges += 1
        except:
            pass
    return edges


def local_var_count(func):
    try:
        return len(func.getLocalVariables())
    except:
        return 0


def scan_function_calls_and_syscall(func):
    called = []
    has_sys = False

    instructions = listing.getInstructions(func.getBody(), True)
    for ins in instructions:
        if not has_sys:
            m = (ins.getMnemonicString() or "").lower()
            if m == "svc":
                has_sys = True

        if not ins.getFlowType().isCall():
            continue

        for ref in ins.getReferencesFrom():
            if ref.getReferenceType() != RefType.UNCONDITIONAL_CALL:
                continue
            tgt = fm.getFunctionAt(ref.getToAddress())
            if tgt:
                called.append((tgt.getName() or "").lower())
            else:
                called.append("")  # unresolved

    return called, has_sys

def write_jsonl_atomic(path, obj_dict):
    p = Paths.get(path)
    parent = p.getParent()
    if parent is not None:
        Files.createDirectories(parent)

    data = (json.dumps(obj_dict) + "\n").encode("utf-8")

    channel = FileChannel.open(
        p,
        StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND
    )
    try:
        lock = channel.lock()
        try:
            channel.write(ByteBuffer.wrap(data))
        finally:
            lock.release()
    finally:
        channel.close()


cfg_edge_total = 0
internal_var_total = 0
internal_func_count = 0
alloc_call_total = 0
syscall_func_count = 0
mach_port_func_count = 0

for func in fm.getFunctions(True):
    if getMonitor().isCancelled():
        break
    try:
        if not is_internal_function(func):
            continue

        internal_func_count += 1
        cfg_edge_total += count_cfg_edges(func)
        internal_var_total += local_var_count(func)

        called_names, has_sys = scan_function_calls_and_syscall(func)

        # allocation calls
        for name in called_names:
            if not name:
                continue
            if any(ex in name for ex in ALLOC_EXCLUDE):
                continue
            if any(k in name for k in ALLOC_KEYWORDS):
                alloc_call_total += 1

        if any((("mach_msg" in n) or ("mach_port" in n)) for n in called_names if n):
            mach_port_func_count += 1

        if has_sys:
            syscall_func_count += 1

    except Exception as e:
        print("[!] Function error in {}: {}".format(func.getName(), e))

record = {
    "ios_version": ios_version,
    "library": binary_name,
    "cfg_edge_count": int(cfg_edge_total),
    "internal_variable_count": int(internal_var_total),
    "internal_function_count": int(internal_func_count),
    "allocation_call_count": int(alloc_call_total),
    "syscall_function_count": int(syscall_func_count),
    "mach_port_function_count": int(mach_port_func_count),
}

write_jsonl_atomic(outpath, record)
print("[+] Wrote metrics for {} -> {}".format(binary_name, outpath))
