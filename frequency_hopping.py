import tkinter as tk
from tkinter import ttk
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class FrequencyHoppingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Frequency Hopping for 5G networks")
        self.root.geometry("800x600")
        self.bands = {
            " (1920-1980 MHz)": (1920, 1980),
            "(3300-3800 MHz)": (3300, 3800),
            "(26500-29500 MHz)": (26500, 29500),
            "(37000-40000 MHz)": (37000, 40000)
        }
        self.label_seq = tk.Label(root, text="Sequence length:")
        self.label_seq.pack(pady=5)
        self.entry_seq = tk.Entry(root)
        self.entry_seq.pack(pady=5)
        self.entry_seq.insert(0, "10")
        self.label_band = tk.Label(root, text="Select 5G frequency bandwidth:")
        self.label_band.pack(pady=5)
        self.band_var = tk.StringVar()
        self.band_dropdown = ttk.Combobox(root, textvariable=self.band_var, values=list(self.bands.keys()), state="readonly")
        self.band_dropdown.pack(pady=5)
        self.band_dropdown.current(0)
        self.button_generate = tk.Button(root, text="Generate", command=self.simulate)
        self.button_generate.pack(pady=10)
        self.result_label = tk.Label(root, text="", wraplength=700, justify="left")
        self.result_label.pack(pady=5)
        self.fig, self.ax = plt.subplots(figsize=(6, 3))
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.root)
        self.canvas.get_tk_widget().pack(pady=10, fill=tk.BOTH, expand=True)
        self.current_index = 0
        self.frequencies = []
        self.sequence = []
        self.normalized = []
        self.simulation_running = False
        self.highlight_line = None
        self.highlight_marker = None

    def normalize_sequence(self, sequence):
        min_val = np.min(sequence)
        max_val = np.max(sequence)
        if max_val == min_val:
            return np.zeros_like(sequence)
        normalized = 127 * (sequence - min_val) / (max_val - min_val)
        return normalized.astype(int)

    def map_to_frequency(self, normalized, band):
        f_min, f_max = self.bands[band]
        frequencies = f_min + (f_max - f_min) * normalized / 127
        return frequencies

    def simulate(self):
        if self.simulation_running:
            self.result_label.config(text="Wait for the allocation of frequencies.")
            return
        try:
            seq_length = int(self.entry_seq.get())
            if seq_length <= 0:
                raise ValueError("The sequence length should be a positive number.")
        except ValueError:
            self.result_label.config(text="Error")
            return
        band = self.band_var.get()
        if not band:
            self.result_label.config(text="Error: Select a 5G band.")
            return
        self.sequence = np.random.uniform(0, 100, seq_length)
        self.normalized = self.normalize_sequence(self.sequence)
        self.frequencies = self.map_to_frequency(self.normalized, band)
        self.ax.clear()
        f_min, f_max = self.bands[band]
        self.ax.set_title(f"Bandwidth {band}")
        self.ax.set_xlabel("Frequency (MHz)")
        self.ax.set_ylabel("Amplitude")
        self.ax.grid(True)
        self.ax.set_ylim(0, 1.2)
        self.ax.set_xlim(f_min - (f_max - f_min) * 0.3, f_max + (f_max - f_min) * 0.3)
        self.fig.tight_layout()
        if self.highlight_line:
            self.highlight_line.set_data([], [])
            self.highlight_marker.set_data([], [])
        else:
            self.highlight_line, = self.ax.plot([], [], 'b-', linewidth=2)
            self.highlight_marker, = self.ax.plot([], [], 'bo', markersize=8)
        self.highlight_line.set_data([self.frequencies[0], self.frequencies[0]], [0, 1])
        self.highlight_marker.set_data([self.frequencies[0]], [1])
        self.canvas.draw()
        self.canvas.flush_events()
        self.current_index = 0
        self.simulation_running = True
        self.button_generate.config(state="disabled")
        self.result_label.config(text=f"Sequence generated: {self.sequence.round(2)}\nNormalized [0,127]: {self.normalized}\nSimulation in progress...")
        self.update_frequency()

    def update_frequency(self):
        if self.current_index >= len(self.frequencies):
            self.simulation_running = False
            self.button_generate.config(state="normal")
            self.result_label.config(text=f"Sequence generated: {self.sequence.round(2)}\nNormalized [0,127]: {self.normalized}\nAllocation completed.")
            if self.highlight_line:
                self.highlight_line.remove()
                self.highlight_line = None
            if self.highlight_marker:
                self.highlight_marker.remove()
                self.highlight_marker = None
            self.canvas.draw()
            self.canvas.flush_events()
            return
        freq = self.frequencies[self.current_index]
        if self.highlight_line:
            self.highlight_line.remove()
        if self.highlight_marker:
            self.highlight_marker.remove()
        self.highlight_line, = self.ax.plot([freq, freq], [0, 1], 'b-', linewidth=2)
        self.highlight_marker, = self.ax.plot([freq], [1], 'bo', markersize=8)
        self.ax.set_ylim(0, 1.2)
        self.ax.set_xlim(min(self.frequencies) - (max(self.frequencies) - min(self.frequencies)) * 0.3, max(self.frequencies) + (max(self.frequencies) - min(self.frequencies)) * 0.3)
        self.canvas.draw()
        self.canvas.flush_events()
        self.result_label.config(text=f"Sequence generated: {self.sequence.round(2)}\nNormalized [0,127]: {self.normalized}\nCurrent frequency (MHz): {freq.round(2)}")
        self.current_index += 1
        self.root.after(1000, self.update_frequency)

if __name__ == "__main__":
    root = tk.Tk()
    app = FrequencyHoppingApp(root)
    root.mainloop()
