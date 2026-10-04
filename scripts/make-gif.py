#!/usr/bin/env python3
"""Assemble captured PNG frames into the README demo GIF.
Usage: make-gif.py <frames-dir> <out.gif> [width]"""
import glob, sys
from PIL import Image
frames_dir, out = sys.argv[1], sys.argv[2]
width = int(sys.argv[3]) if len(sys.argv) > 3 else 1000
files = sorted(glob.glob(frames_dir + "/frame-*.png"))
imgs = []
for f in files:
    im = Image.open(f).convert("RGB")
    h = round(im.height * width / im.width)
    imgs.append(im.resize((width, h), Image.LANCZOS))
# Drop identical consecutive frames, holding the previous one longer instead.
frames, durations = [], []
for im in imgs:
    if frames and im.tobytes() == frames[-1].tobytes():
        durations[-1] += 400
    else:
        frames.append(im)
        durations.append(400)
durations[-1] += 2500
pal = [f.quantize(colors=128, method=Image.Quantize.MEDIANCUT) for f in frames]
pal[0].save(out, save_all=True, append_images=pal[1:], duration=durations, loop=0, optimize=True)
print(f"{len(frames)} distinct frames from {len(files)} -> {out}")
