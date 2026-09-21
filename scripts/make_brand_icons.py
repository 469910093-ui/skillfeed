"""从慵懒躺沙发的肥嘚透明稿生成浏览器小标。"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "docs" / "brand" / "assets" / "logo-feide-transparent.png"
OUT = ROOT / "docs" / "brand" / "assets"
BG = (244, 247, 255, 255)  # 冰紫壳底，和 brand-guide 一致


def _trim(im: Image.Image, pad: int = 8) -> Image.Image:
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


def compose(size: int, *, margin_ratio: float = 0.10) -> Image.Image:
    blob = _trim(Image.open(SRC).convert("RGBA"))
    canvas = _rounded_bg(size, radius=max(18, size // 5))
    inner = int(size * (1 - 2 * margin_ratio))
    scale = min(inner / blob.width, inner / blob.height)
    w, h = max(1, int(blob.width * scale)), max(1, int(blob.height * scale))
    blob = blob.resize((w, h), Image.Resampling.LANCZOS)
    x, y = (size - w) // 2, (size - h) // 2 + size // 40
    canvas.alpha_composite(blob, (x, y))
    return canvas.filter(ImageFilter.SMOOTH_MORE)


def main() -> None:
    if not SRC.exists():
        raise SystemExit(f"missing {SRC}")
    square = compose(512)
    square.save(OUT / "logo-sofa.png", format="PNG")
    compose(180, margin_ratio=0.08).save(OUT / "apple-touch-icon.png", format="PNG")
    compose(48, margin_ratio=0.06).save(OUT / "favicon.png", format="PNG")
    ico_src = compose(128, margin_ratio=0.04)
    ico_src.save(
        OUT / "favicon.ico",
        format="ICO",
        sizes=[(16, 16), (32, 32), (48, 48)],
    )
    print("wrote", OUT / "logo-sofa.png")
    print("wrote", OUT / "favicon.ico")
    print("wrote", OUT / "favicon.png")
    print("wrote", OUT / "apple-touch-icon.png")


if __name__ == "__main__":
    main()
