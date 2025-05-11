from __future__ import annotations
import argparse, hashlib, hmac, logging, os, random, sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PIL import Image
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk
from customtkinter import CTkFrame, CTkLabel, CTkButton, CTkCheckBox, CTkEntry, CTkImage

PACKET = 1024
BLACK  = b"\0" * PACKET
HMAC_KEY = hashlib.sha256(b"SLINK_HMAC_KEY").digest()

def log_init(level: str = "INFO") -> None:
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO),
                        format="%(levelname)-8s | %(message)s", stream=sys.stdout)

def chunks(buf: bytes, n: int = PACKET) -> List[bytes]:
    return [buf[i:i+n] for i in range(0, len(buf), n)]

def img2bytes(p: Path) -> bytes:
    return Image.open(p).convert("RGB").tobytes()

def bytes2img(b: bytes, wh: Tuple[int, int]) -> Image.Image:
    need = wh[0] * wh[1] * 3
    if len(b) < need:
        b += b"\0" * (need - len(b))
    return Image.frombytes("RGB", wh, b[:need])

def rand_block() -> bytes:
    return os.urandom(PACKET)

def ber_ok(src: List[bytes], dst: List[bytes], ok: List[bool]) -> float:
    good_src = b"".join(s for s, f in zip(src, ok) if f)
    good_dst = b"".join(d for d, f in zip(dst, ok) if f)
    if not good_src:
        return 0.0
    return sum(sa != da for sa, da in zip(good_src, good_dst)) / len(good_src)

def gk() -> bytes: return AESGCM.generate_key(256)
def aes_enc(pl: bytes, k: bytes) -> Tuple[bytes, bytes]:
    n = os.urandom(12); return AESGCM(k).encrypt(n, pl, None), n
def aes_dec(ct: bytes, n: bytes, k: bytes) -> bytes: return AESGCM(k).decrypt(n, ct, None)
def mac(data: bytes) -> bytes: return hmac.new(HMAC_KEY, data, hashlib.sha256).digest()

@dataclass
class Packet:
    seq: int
    payload: bytes
    nonce: bytes | None = None
    tag: bytes | None = None

class Channel:
    def __init__(self, aes: bool, hmac_on: bool):
        self.aes, self.hmac = aes, hmac_on
        self.key = gk() if aes else None
    def tx(self, p: Packet) -> Packet:
        if self.aes and self.key:
            p.payload, p.nonce = aes_enc(p.payload, self.key)
        if self.hmac:
            p.tag = mac(p.payload)
        return p
    def rx(self, p: Packet, blk_len: int) -> Tuple[bytes, bool]:
        ok = True
        if self.hmac:
            ok &= p.tag is not None and hmac.compare_digest(mac(p.payload), p.tag)
        data = p.payload
        if self.aes and self.key:
            try: data = aes_dec(p.payload, p.nonce, self.key)
            except Exception: ok = False; data = b""
        if not ok:
            data = BLACK if blk_len == PACKET else b"\0" * blk_len
        return data, ok

class MITM:
    def __init__(self, t: float, d: float, i: float): self.t, self.d, self.i = t, d, i
    def act(self, p: Packet) -> List[Packet]:
        out = []
        if random.random() < self.d:
            return out
        if random.random() < self.t:
            p.payload = rand_block()
        out.append(p)
        if random.random() < self.i:
            out.append(Packet(p.seq + 10_000_000, rand_block()))
        return out

def simulate(src: bytes, *, use_aes: bool, use_hmac: bool,
             attacker: MITM | None) -> Tuple[List[bytes], List[bool], List[bytes]]:
    chan = Channel(use_aes, use_hmac)
    src_chunks = chunks(src); n = len(src_chunks)
    recv: Dict[int, bytes] = {}; ok_map: Dict[int, bool] = {}

    for seq, raw in enumerate(src_chunks):
        for f in (attacker.act(chan.tx(Packet(seq, raw))) if attacker else [chan.tx(Packet(seq, raw))]):
            if f.seq >= n or f.seq in recv:
                continue
            data, ok = chan.rx(f, len(raw))
            if not (use_aes or use_hmac):
                ok = True
            recv[f.seq] = data; ok_map[f.seq] = ok

    for seq in range(n):
        if seq not in recv:
            blk = BLACK if len(src_chunks[seq]) == PACKET else b"\0" * len(src_chunks[seq])
            recv[seq] = blk; ok_map[seq] = False if (use_aes or use_hmac) else True

    dst_chunks = [recv[i] for i in range(n)]
    ok_flags   = [ok_map[i] for i in range(n)]
    return dst_chunks, ok_flags, src_chunks

class GUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(f"Secure Space Link"); self.geometry("1200x750")
        ctk.set_default_color_theme("blue"); ctk.set_appearance_mode("System")
        self.path: Path | None = None; self.orig = None; self.dist = None
        self._build_left(); self._build_right()

    def _build_left(self):
        pane = CTkFrame(self, width=280); pane.grid(row=0, column=0, padx=10, pady=10, sticky="nsw")
        for r in range(9): pane.rowconfigure(r, weight=0)
        pane.rowconfigure(9, weight=1)

        CTkButton(pane, text="Выбрать изображение", command=self._pick).grid(
            row=0, column=0, padx=10, pady=(12, 6), sticky="ew")

        self.v_t = tk.StringVar(master=self, value="0.0")
        self.v_d = tk.StringVar(master=self, value="0.0")
        self.v_i = tk.StringVar(master=self, value="0.0")
        self._entry(pane, "Tamper", self.v_t, 1)
        self._entry(pane, "Drop",   self.v_d, 2)
        self._entry(pane, "Inject", self.v_i, 3)

        self.f_mitm  = tk.BooleanVar(master=self, value=True)
        self.f_aes   = tk.BooleanVar(master=self, value=True)
        self.f_hmac  = tk.BooleanVar(master=self, value=True)
        CTkCheckBox(pane, text="Enable MITM",   variable=self.f_mitm).grid(row=4,column=0,sticky="w",padx=12,pady=4)
        CTkCheckBox(pane, text="AES encryption",variable=self.f_aes ).grid(row=5,column=0,sticky="w",padx=12)
        CTkCheckBox(pane, text="HMAC integrity",variable=self.f_hmac).grid(row=6,column=0,sticky="w",padx=12)

        CTkButton(pane, text="Run simulation", command=self._run).grid(
            row=7, column=0, padx=10, pady=10, sticky="ew")

        self.res = CTkLabel(pane, text="", justify="left")
        self.res.grid(row=9, column=0, sticky="sw", padx=10, pady=6)

    def _entry(self, par, caption, var, row):
        fr = CTkFrame(par, fg_color="transparent")
        fr.grid(row=row, column=0, sticky="ew", padx=12, pady=4)
        fr.columnconfigure(1, weight=1)
        CTkLabel(fr, text=f"{caption}:").grid(row=0, column=0, sticky="w")
        CTkEntry(fr, textvariable=var, width=80).grid(row=0, column=1, sticky="e")

    def _build_right(self):
        pane = CTkFrame(self, corner_radius=12)
        pane.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        pane.columnconfigure((0, 1), weight=1)
        pane.rowconfigure(0, weight=1)

        self.l_orig = CTkLabel(pane, text="Original\nnot loaded")
        self.l_orig.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        self.l_dist = CTkLabel(pane, text="Corrupted\nwill appear here")
        self.l_dist.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)

    def _pick(self):
        fname = filedialog.askopenfilename(filetypes=[("Images", "*.png;*.jpg;*.jpeg")])
        if not fname: return
        self.path = Path(fname); self.orig = Image.open(self.path).convert("RGB")
        self._show(self.orig, self.l_orig)
        self.l_dist.configure(text="Corrupted\nwill appear here", image=None)
        self.res.configure(text="")

    def _run(self):
        if not self.path:
            messagebox.showerror("Ошибка", "Выберите изображение."); return
        try:
            t = float(self.v_t.get().replace(",", ".") or 0)
            d = float(self.v_d.get().replace(",", ".") or 0)
            i = float(self.v_i.get().replace(",", ".") or 0)
        except ValueError:
            messagebox.showerror("Ошибка", "Tamper/Drop/Inject — не число"); return

        attacker = MITM(t, d, i) if self.f_mitm.get() else None
        src = img2bytes(self.path)
        dst, ok, src_chunks = simulate(
            src,
            use_aes=self.f_aes.get(),
            use_hmac=self.f_hmac.get(),
            attacker=attacker,
        )
        self.res.configure(text=f"Integrity {sum(ok)}/{len(ok)} ({sum(ok)/len(ok):.2%})\n"
                                f"BER {ber_ok(src_chunks,dst,ok):.4%}")

        self.dist = bytes2img(b"".join(dst), self.orig.size)
        self._show(self.dist, self.l_dist)

    def _show(self, im: Image.Image, lbl: CTkLabel):
        thumb = im.copy(); thumb.thumbnail((550, 550), Image.Resampling.LANCZOS)
        tk_img = CTkImage(thumb, size=thumb.size)
        lbl.configure(image=tk_img, text=""); lbl.image = tk_img

def float_range(expr: str):
    if ":" not in expr:
        return [float(expr)]
    a,b,s=map(float,expr.split(":"))
    return [a+i*s for i in range(int(round((b-a)/s))+1)]

def cli():
    ap=argparse.ArgumentParser("Secure Space Link")
    ap.add_argument("--gui",action="store_true"); ap.add_argument("--log",default="info")
    sub=ap.add_subparsers(dest="mode")

    s=sub.add_parser("single"); s.add_argument("image"); s.add_argument("--tamper",type=float,default=0)
    s.add_argument("--drop",type=float,default=0); s.add_argument("--inject",type=float,default=0)
    s.add_argument("--mitm",action="store_true"); s.add_argument("--no-enc",action="store_true"); s.add_argument("--no-int",action="store_true")
    s.add_argument("--out")

    b=sub.add_parser("batch"); b.add_argument("image"); b.add_argument("--tamper",default="0:0.4:0.05")
    b.add_argument("--drop",type=float,default=0); b.add_argument("--inject",type=float,default=0)
    b.add_argument("--no-enc",action="store_true"); b.add_argument("--no-int",action="store_true"); b.add_argument("--csv")
    return ap.parse_args()

def main():
    args=cli(); log_init(args.log)
    if args.gui or args.mode is None:
        GUI().mainloop(); return
    if args.mode=="single":
        att=MITM(args.tamper,args.drop,args.inject) if args.mitm else None
        src=img2bytes(Path(args.image))
        dst, ok, src_chunks = simulate(src, use_aes=not args.no_enc, use_hmac=not args.no_int, attacker=att)
        print("Integrity",f"{sum(ok)}/{len(ok)}","BER",f"{ber_ok(src_chunks,dst,ok):.4%}")
        if args.out:
            bytes2img(b"".join(dst), Image.open(args.image).size).save(args.out)
    elif args.mode=="batch":
        src=img2bytes(Path(args.image)); rows=[]
        for t in float_range(args.tamper):
            dst,ok,src_chunks=simulate(src,use_aes=not args.no_enc,use_hmac=not args.no_int,
                                        attacker=MITM(t,args.drop,args.inject))
            rows.append((t,ber_ok(src_chunks,dst,ok))); logging.info("%.2f\t%.4f",*rows[-1])
        if args.csv: open(args.csv,"w").write("tamper,ber\n"+"\n".join(f"{t},{b}" for t,b in rows))

if __name__=="__main__":
    main()
