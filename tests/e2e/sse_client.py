# Reads an event stream on stdin; "streamed" if the events arrived spread
# out over time rather than together at the end.
import sys, time
times = [time.monotonic() for line in sys.stdin if line.startswith("data:")]
print("streamed" if len(times) == 3 and times[-1] - times[0] > 0.7 else f"got {len(times)} over {times[-1] - times[0] if times else 0:.2f}s")
