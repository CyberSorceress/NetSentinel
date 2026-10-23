"""
NetSentinel - Live Packet Capture
Real-time network traffic sniffer with BPF filtering, thread-safe queuing, and callback hooks.
"""

import logging
import queue
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from scapy.all import AsyncSniffer, conf, get_if_list

from .pcap_parser import PacketParser

logger = logging.getLogger("NetSentinel.LiveCapture")


class LiveCaptureMonitor:
    """Manages asynchronous live packet capture on authorized network interfaces."""

    def __init__(self, interface: Optional[str] = None, bpf_filter: Optional[str] = None,
                 packet_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
                 max_queue_size: int = 10000):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.packet_callback = packet_callback
        self.packet_queue: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self.is_running = False
        self._sniffer: Optional[AsyncSniffer] = None
        self._parser = PacketParser.__new__(PacketParser)
        self._parser.pcap_path = "live_capture"
        self.packet_count = 0
        self.start_time: Optional[float] = None
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None

    @staticmethod
    def get_available_interfaces() -> List[str]:
        """Returns list of network interface names available on the host."""
        try:
            return get_if_list()
        except Exception as e:
            logger.warning(f"Failed to list network interfaces: {e}")
            return []

    def _packet_handler(self, scapy_pkt: Any):
        """Called for every incoming Scapy packet from the network card."""
        if not self.is_running:
            return
        self.packet_count += 1
        try:
            meta = self._parser.parse_packet_metadata(scapy_pkt, self.packet_count)
            meta["pcap_source"] = "LIVE_INTERFACE"

            # Put in queue if room
            if not self.packet_queue.full():
                self.packet_queue.put_nowait(meta)

            # Trigger optional live callback
            if self.packet_callback:
                self.packet_callback(meta)
        except Exception as e:
            logger.debug(f"Error handling live packet: {e}")

    def start(self, count: int = 0, timeout: Optional[int] = None) -> bool:
        """Starts asynchronous packet capture."""
        if self.is_running:
            return True

        self.packet_count = 0
        self.start_time = time.time()
        self.is_running = True
        self._stop_event.clear()

        try:
            sniffer_kwargs: Dict[str, Any] = {
                "prn": self._packet_handler,
                "store": False,
            }
            if self.interface:
                sniffer_kwargs["iface"] = self.interface
            if self.bpf_filter:
                sniffer_kwargs["filter"] = self.bpf_filter
            if count > 0:
                sniffer_kwargs["count"] = count
            if timeout and timeout > 0:
                sniffer_kwargs["timeout"] = timeout

            self._sniffer = AsyncSniffer(**sniffer_kwargs)
            self._sniffer.start()
            logger.info(f"Live capture started on iface={self.interface or 'default'}, filter='{self.bpf_filter or ''}'")
            return True
        except Exception as e:
            self.is_running = False
            logger.error(f"Failed to start live capture: {e}")
            raise RuntimeError(f"Live capture failed: {e}. Note: Raw packet capture requires Administrator/Npcap permissions.")

    def stop(self) -> Dict[str, Any]:
        """Stops the active packet capture and returns capture session statistics."""
        if not self.is_running:
            return {"status": "not_running", "packets_captured": self.packet_count}

        self.is_running = False
        self._stop_event.set()
        duration = time.time() - (self.start_time or time.time())

        if self._sniffer and self._sniffer.running:
            try:
                self._sniffer.stop()
            except Exception as e:
                logger.debug(f"Error stopping sniffer: {e}")

        logger.info(f"Live capture stopped. Captured {self.packet_count} packets in {duration:.2f}s")
        return {
            "status": "stopped",
            "packets_captured": self.packet_count,
            "duration_seconds": round(duration, 2),
            "packets_per_sec": round(self.packet_count / duration if duration > 0 else 0, 2)
        }

    def get_queued_packets(self, max_items: int = 100) -> List[Dict[str, Any]]:
        """Drains up to max_items packets from the thread-safe queue."""
        packets = []
        while not self.packet_queue.empty() and len(packets) < max_items:
            try:
                packets.append(self.packet_queue.get_nowait())
            except queue.Empty:
                break
        return packets
