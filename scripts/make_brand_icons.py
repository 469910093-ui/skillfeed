"""从慵懒躺沙发的肥嘚透明稿生成浏览器小标。

先在 1024 里排版，再 LANCZOS 缩到各尺寸。禁止 SMOOTH：小标发糊就是它造成的。
16/32/48 缩完后轻轻锐化，把眼睛和嘴的边找回来。
"""

from __future__ import annotations

import io
import struct
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "docs" / "brand" / "assets" / "logo-feide-transparent.png"
OUT = ROOT / "docs" / "brand" / "assets"
BG = (244, 247, 255, 255)  # 冰紫壳底，和 brand-guide 一致


def _trim(im: Image.Image, pad: int = 4) -> Image.Image:
    bbox = im.getbbox()
    if not bbox:
        return im
    l, t, r, b = bbox
    l = max(0, l - pad)
    t = max(0, t - pad)
    r = min(im.width, r + pad)
    b = min(im.height, b + pad)
    return im.crop((l, t, r, b))


def _rounded_bg(size: int, radius: int) -> Image.Image:
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, size - 1, size - 1), radius=radius, fill=255)
    color = Image.new("RGBA", (size, size), BG)
    canvas.paste(color, mask=mask)
    return canvas


def compose_master(*, margin_ratio: float = 0.05) -> Image.Image:
    """按源图像素排版。源图只有 512，禁止先放大再缩小。"""
    blob = _trim(Image.open(SRC).convert("RGBA"))
    needed = int(max(blob.width, blob.height) / (1 - 2 * margin_ratio))
    size = max(blob.width, blob.height, needed)
    size += size % 2
    canvas = _rounded_bg(size, radius=size // 5)
    inner = int(size * (1 - 2 * margin_ratio))
    if blob.width > inner or blob.height > inner:
        scale = min(inner / blob.width, inner / blob.height)
        w, h = max(1, int(blob.width * scale)), max(1, int(blob.height * scale))
        blob = blob.resize((w, h), Image.Resampling.LANCZOS)
    else:
        w, h = blob.width, blob.height
    x, y = (size - w) // 2, (size - h) // 2 + size // 50
    canvas.alpha_composite(blob, (x, y))
    return canvas


def _downscale(master: Image.Image, size: int) -> Image.Image:
    out = master.resize((size, size), Image.Resampling.LANCZOS)
    if size <= 16:
        out = out.filter(ImageFilter.UnsharpMask(radius=0.6, percent=130, threshold=1))
    elif size <= 48:
        out = out.filter(ImageFilter.UnsharpMask(radius=0.8, percent=150, threshold=1))
    return out


def write_ico(path: Path, frames: list[Image.Image]) -> None:
    """把多张 PNG 打进 ICO。Pillow 的 sizes= 经常只留下最大的一帧。"""
    entries = []
    blobs = []
    offset = 6 + 16 * len(frames)
    for frame in frames:
        buf = io.BytesIO()
        frame.save(buf, format="PNG")
        data = buf.getvalue()
        side = frame.width
        stored = 0 if side >= 256 else side
        entries.append(struct.pack("<BBBBHHII", stored, stored, 0, 0, 1, 32, len(data), offset))
        blobs.append(data)
        offset += len(data)
    with path.open("wb") as fh:
        fh.write(struct.pack("<HHH", 0, 1, len(frames)))
        fh.write(b"".join(entries))
        fh.write(b"".join(blobs))


def main() -> None:
    if not SRC.exists():
        raise SystemExit(f"missing {SRC}")
    master = compose_master()
    side = min(master.width, 512)
    _downscale(master, side).save(OUT / "logo-sofa.png", format="PNG")
    _downscale(master, 180).save(OUT / "apple-touch-icon.png", format="PNG")
    # 192：视网膜 tab 按 2x/3x 显示时还有余量，不要再交 48px 糊点。
    _downscale(master, 192).save(OUT / "favicon.png", format="PNG")
    write_ico(
        OUT / "favicon.ico",
        [_downscale(master, size) for size in (16, 32, 48)],
    )
    print("wrote", OUT / "logo-sofa.png")
    print("wrote", OUT / "favicon.ico")
    print("wrote", OUT / "favicon.png")
    print("wrote", OUT / "apple-touch-icon.png")


if __name__ == "__main__":
    main()
