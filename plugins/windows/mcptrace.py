"""MCP artifacts in Windows process virtual memory (Volatility 3)."""

from volatility3.framework import interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.windows import pslist

from mcptrace.volatility import MCPTraceMixin


class MCPTrace(MCPTraceMixin, interfaces.plugins.PluginInterface):
    """Extract MCP/JSON-RPC candidates and policy findings from Windows VADs."""

    _required_framework_version = (2, 28, 0)
    _version = (0, 2, 0)
    _target_os = "windows"
    _region_kind = "vad"

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Windows x64 kernel", architectures=["Intel64"]
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            *cls.common_requirements(),
        ]

    def _list_processes(self):
        return pslist.PsList.list_processes(
            context=self.context,
            kernel_module_name=self.config["kernel"],
            filter_func=pslist.PsList.create_pid_filter(self.config.get("pid")),
        )

    @staticmethod
    def _pid(proc):
        return int(proc.UniqueProcessId)

    @staticmethod
    def _process_name(proc):
        return utility.array_to_string(proc.ImageFileName)

    @staticmethod
    def _process_layer_name(proc):
        return proc.add_process_layer()

    @staticmethod
    def _regions(proc):
        for vad in proc.get_vad_root().traverse():
            yield int(vad.get_start()), int(vad.get_size())
