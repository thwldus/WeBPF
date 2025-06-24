import subprocess
import json
import time
import random
from opentelemetry import trace
from opentelemetry.trace import TraceFlags
from opentelemetry.sdk.resources import Resource
from opentelemetry.trace import SpanContext, NonRecordingSpan, set_span_in_context
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

# OpenTelemetry 설정
resource = Resource.create({"service.name": "ebpf-bridge"})
provider = TracerProvider(resource=resource)
trace.set_tracer_provider(provider)
otlp_exporter = OTLPSpanExporter(endpoint="http://localhost:4318/v1/traces")
span_processor = BatchSpanProcessor(otlp_exporter)
provider.add_span_processor(span_processor)
tracer = trace.get_tracer(__name__)

# === PID → (Trace ID, Span ID) 매핑 ===
pid_to_trace = {}
pid_to_span = {}

def gen_id(bits=64):
    return hex(random.getrandbits(bits))[2:]

# === 이벤트 처리 ===
def process_event(event):
    evt_type = event.get("type")
    pid = event.get("pid")
    ppid = event.get("ppid")
    comm = event.get("comm", "unknown")

    trace_id = pid_to_trace.get(ppid, gen_id(128))
    parent_span_id = pid_to_span.get(ppid)

    # 새로운 Span ID
    span_id = gen_id(64)
    pid_to_span[pid] = span_id
    pid_to_trace[pid] = trace_id

    # 부모 컨텍스트 (없으면 root span)
    parent_ctx = None
    if parent_span_id:
        parent_context = SpanContext(
            trace_id=int(trace_id, 16),
            span_id=int(parent_span_id, 16),
            is_remote=False,
            trace_flags=TraceFlags(TraceFlags.SAMPLED),
            trace_state={}
        )
        parent_ctx = set_span_in_context(NonRecordingSpan(parent_context))

    with tracer.start_as_current_span(
        name=f"{evt_type}:{comm}",
        context=parent_ctx
    ) as span:
        span.set_attribute("process.pid", pid)
        span.set_attribute("process.ppid", ppid)
        span.set_attribute("process.name", comm)
        span.set_attribute("event.type", evt_type)

        # 이벤트별 추가 정보
        if evt_type == "exit":
            span.set_attribute("exit.code", event.get("exit_code"))
            span.set_attribute("duration.ns", event.get("duration_ns"))

        elif evt_type == "open":
            span.set_attribute("file.name", event.get("filename"))

        elif evt_type == "tcp":
            span.set_attribute("tcp.saddr", event.get("saddr"))
            span.set_attribute("tcp.daddr", event.get("daddr"))
            span.set_attribute("tcp.sport", event.get("sport"))
            span.set_attribute("tcp.dport", event.get("dport"))

# 실행 및 이벤트 수신 ===
def main():
    proc = subprocess.Popen(["sudo", "./snoop_user"], stdout=subprocess.PIPE, text=True)
    
    for line in proc.stdout:
        try:
            event = json.loads(line.strip())
            process_event(event)
        except json.JSONDecodeError:
            # snoop_user 실행 시 안내 문구
            # print(line.strip())
            pass

if __name__ == "__main__":
    main()

