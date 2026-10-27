"""MCP artifacts in Linux x86-64 process virtual memory (Volatility 3)."""

from volatility3.framework import interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist

from mcptrace.volatility import MCPTraceMixin, SkipProcess, UnsupportedMemoryLayout


class MCPTrace(MCPTraceMixin, interfaces.plugins.PluginInterface):
    """Extract MCP/JSON-RPC candidates and policy findings from Linux VMAs."""

    _required_framework_version = (2, 28, 0)
    _version = (0, 2, 0)
    _target_os = "linux"
    _region_kind = "vma"

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Linux x86-64 kernel", architectures=["Intel64"]
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 0, 0)
            ),
            *cls.common_requirements(),
        ]

    def _list_processes(self):
        # Group leaders own the process address space. Do not scan it again for
        # every user thread. PID selection uses the same semantics as linux.pslist.
        return pslist.PsList.list_tasks(
            context=self.context,
            vmlinux_module_name=self.config["kernel"],
            filter_func=pslist.PsList.create_pid_filter(self.config.get("pid")),
            include_threads=False,
        )

    @staticmethod
    def _pid(task):
        return int(task.tgid)

    @staticmethod
    def _process_name(task):
        return utility.array_to_string(task.comm)

    @staticmethod
    def _process_layer_name(task):
        # Never fall back to active_mm: kernel threads can borrow another task's
        # address space, which would assign its artifacts to the wrong process.
        if not task.mm:
            raise SkipProcess("no-user-address-space")
        return task.add_process_layer()

    @staticmethod
    def _regions(task):
        try:
            # Volatility selects the legacy mmap list or the modern Maple Tree.
            for vma in task.mm.get_vma_iter():
                start, end = int(vma.vm_start), int(vma.vm_end)
                yield start, end - start  # vm_end is exclusive.
        except AttributeError as exc:
            raise UnsupportedMemoryLayout(
                "Linux mm/VMA layout is unsupported by the installed Volatility symbols/framework"
            ) from exc
