from pydantic import BaseModel


class DeviceCreateRequest(BaseModel):
    label: str | None = None


class CapabilityIssueRequest(BaseModel):
    action: str = "read"
    resource: str = "iot:device:example"


class AuthorizeRequest(BaseModel):
    action: str = "read"
    resource: str = "iot:device:example"
    tamper_signature: bool = False


class RevokeRequest(BaseModel):
    reason: str = "dashboard capability revocation"


class CleanStateRequest(BaseModel):
    confirm: str
    reset_fabric: bool = False
    reset_runtime_data: bool = True
    normalize_line_endings: bool = False


class ScenarioRunRequest(BaseModel):
    device_id: str


class BenchmarkRunRequest(BaseModel):
    benchmark_type: str
    runs: int = 1
    warmup_runs: int = 0


class BenchmarkSuiteRunRequest(BaseModel):
    runs: int = 1
    warmup_runs: int = 0
