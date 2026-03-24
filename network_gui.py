import threading
import queue
import sys
import tkinter as tk
from collections import Counter

try:
    from scapy.all import sniff
    from scapy.layers.inet import IP
except Exception as e:
    sniff = None

from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


class NetworkMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Traffic Monitor")

        # Data
        self.packet_count = Counter()
        self.queue = queue.Queue()
        self.sniff_thread = None
        self.stop_event = threading.Event()

        # UI - text log
        self.text_area = tk.Text(self.root, height=15, width=60)
        self.text_area.pack(padx=8, pady=6)

        # Buttons
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=4)

        self.start_btn = tk.Button(btn_frame, text="Start Monitoring", command=self.start_monitor)
        self.start_btn.pack(side=tk.LEFT, padx=4)

        self.stop_btn = tk.Button(btn_frame, text="Stop", command=self.stop_monitor, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=4)

        self.status_label = tk.Label(btn_frame, text="Stopped")
        self.status_label.pack(side=tk.LEFT, padx=8)

        # Matplotlib figure embedded in Tk — 2x2 grid showing all charts
        self.fig = Figure(figsize=(10, 8))
        self.axes = [self.fig.add_subplot(2, 2, i + 1) for i in range(4)]
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.root)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        # Poll queue periodically
        self.root.after(500, self._process_queue)

    def _packet_callback(self, packet):
        # Called in sniffing thread; push data to queue for main thread to handle
        if IP in packet:
            src = packet[IP].src
            self.queue.put(("ip", src))

    def _sniff_loop(self):
        # Runs in background thread
        if sniff is None:
            self.queue.put(("error", "scapy import failed. Install scapy and run as admin/root."))
            return

        try:
            sniff(prn=self._packet_callback, store=False, stop_filter=lambda x: self.stop_event.is_set())
        except Exception as e:
            self.queue.put(("error", str(e)))

    def start_monitor(self):
        if self.sniff_thread and self.sniff_thread.is_alive():
            return

        self.stop_event.clear()
        self.sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniff_thread.start()
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_label.config(text="Running")
        self._log("Monitoring started. (Run as admin/root if needed)")

    def stop_monitor(self):
        if not self.sniff_thread:
            return
        self.stop_event.set()
        self.sniff_thread = None
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_label.config(text="Stopped")
        self._log("Monitoring stopped.")

    def _log(self, msg):
        self.text_area.insert(tk.END, msg + "\n")
        self.text_area.see(tk.END)

    def _process_queue(self):
        updated = False
        while True:
            try:
                kind, payload = self.queue.get_nowait()
            except queue.Empty:
                break

            if kind == "ip":
                self.packet_count[payload] += 1
                self._log(f"IP: {payload}  (count: {self.packet_count[payload]})")
                updated = True
            elif kind == "error":
                self._log("Error: " + payload)

        if updated:
            self._update_plot()

        self.root.after(500, self._process_queue)

    def _update_plot(self):
        # Clear all subplots
        for ax in self.axes:
            ax.clear()

        if not self.packet_count:
            for ax in self.axes:
                ax.set_title("No packets yet")
            self.canvas.draw()
            return

        # Show top 10 talkers for plots that use top N
        items = self.packet_count.most_common(10)
        ips = [i for i, _ in items]
        counts = [c for _, c in items]

        # Bar (top-left)
        ax = self.axes[0]
        ax.bar(ips, counts, color="tab:blue")
        ax.set_xticklabels(ips, rotation=45, ha="right")
        ax.set_ylabel("Packets")
        ax.set_title("Top IPs by Packet Count (Bar)")

        # Line (top-right)
        ax = self.axes[1]
        ax.plot(range(len(counts)), counts, marker='o', linestyle='-')
        ax.set_xticks(range(len(ips)))
        ax.set_xticklabels(ips, rotation=45, ha="right")
        ax.set_ylabel("Packets")
        ax.set_title("Top IPs by Packet Count (Line)")

        # Pie (bottom-left) - show top 10 as share
        ax = self.axes[2]
        ax.pie(counts, labels=ips, autopct='%1.1f%%', startangle=90)
        ax.set_title("Top IPs by Packet Share (Pie)")

        # Box (bottom-right) - distribution across all IPs
        ax = self.axes[3]
        all_counts = list(self.packet_count.values())
        ax.boxplot(all_counts)
        ax.set_title("Packet Count Distribution (Box)")

        self.fig.tight_layout()
        self.canvas.draw()


def main():
    root = tk.Tk()
    app = NetworkMonitorApp(root)
    root.protocol("WM_DELETE_WINDOW", lambda: (app.stop_monitor(), root.destroy()))
    root.mainloop()


if __name__ == "__main__":
    main()
