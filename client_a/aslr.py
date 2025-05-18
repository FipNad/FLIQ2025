import ctypes
import os
import requests

# --- Constants ---
PROT_READ = 0x1
PROT_WRITE = 0x2
MAP_PRIVATE = 0x02
MAP_ANONYMOUS = 0x20
MAP_FIXED_NOREPLACE = 0x100000  # Linux 4.17+

PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")

libc = ctypes.CDLL("libc.so.6", use_errno=True)

class QRNGAllocator:
    def __init__(self, base_range=(0x40000000, 0x7FFFFFFF)):
        self.base_min, self.base_max = base_range

    def get_qrng_uint32(self):
        try:
            response = requests.get(
                "https://qrng.anu.edu.au/API/jsonI.php?length=1&type=uint32", timeout=3)
            if response.status_code == 200:
                return response.json()["data"][0]
        except Exception as e:
            print(f"[!] QRNG fetch failed, using fallback: {e}")
        return int.from_bytes(os.urandom(4), 'big')

    def align_down(self, addr):
        return addr & ~(PAGE_SIZE - 1)

    def allocate(self, size):
        assert size % PAGE_SIZE == 0, "Size must be page-aligned"

        rnd = self.get_qrng_uint32()
        raw_addr = self.base_min + (rnd % (self.base_max - self.base_min - size))
        aligned_addr = self.align_down(raw_addr)

        addr = libc.mmap(
            ctypes.c_void_p(aligned_addr),
            ctypes.c_size_t(size),
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
            -1,
            0
        )

        if addr == -1 or addr is None or addr == ctypes.c_void_p(-1).value:
            errno = ctypes.get_errno()
            raise OSError(errno, f"mmap failed at 0x{aligned_addr:x}: {os.strerror(errno)}")

        print(f"[+] Allocated {size} bytes at: 0x{addr:x}")
        return addr

    def free(self, addr, size):
        result = libc.munmap(ctypes.c_void_p(addr), ctypes.c_size_t(size))
        if result != 0:
            errno = ctypes.get_errno()
            raise OSError(errno, os.strerror(errno))
        print(f"[-] Freed memory at: 0x{addr:x}")


# --- Example Usage ---
if __name__ == "__main__":
    allocator = QRNGAllocator()
    try:
        size = PAGE_SIZE  # Ensure size is page-aligned
        addr = allocator.allocate(size)

        # Optional: write to memory
        test = b"Quantum mmap test\0"
        ctypes.memmove(addr, test, len(test))
        print("[*] Read from memory:", ctypes.string_at(addr, len(test)).decode())

        allocator.free(addr, size)
    except Exception as e:
        print("Error:", e)
