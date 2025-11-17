#!/usr/bin/env python3
"""Generate placeholder capture images summarizing security flows."""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

WIDTH, HEIGHT = 1200, 675
BG_COLOR = (7, 18, 30)
PRIMARY = (64, 213, 255)
SECONDARY = (140, 250, 120)
TEXT = (240, 240, 240)

OUTPUT = Path("docs/evidence/captura_login.png")
OUTPUT.parent.mkdir(parents=True, exist_ok=True)

img = Image.new("RGB", (WIDTH, HEIGHT), BG_COLOR)
draw = ImageDraw.Draw(img)

try:
    font_title = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 48)
    font_body = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 28)
except OSError:
    font_title = ImageFont.load_default()
    font_body = ImageFont.load_default()

sections = [
    ("Registro", "Argon2id + validaciones de complejidad"),
    ("Login", "JWTs en cookies HttpOnly, bloqueo de IP y cuenta"),
    ("Refresh", "Rotación obligatoria con revocación y jti"),
    ("Cambio de contraseña", "Revoca todos los refresh tokens activos"),
]

draw.text((40, 40), "Sistema de Login Seguro", fill=PRIMARY, font=font_title)
origin_y = 140
for title, detail in sections:
    draw.rounded_rectangle((40, origin_y, WIDTH - 40, origin_y + 100), radius=20, outline=PRIMARY, width=3)
    draw.text((60, origin_y + 15), title, fill=SECONDARY, font=font_body)
    draw.text((60, origin_y + 55), detail, fill=TEXT, font=font_body)
    origin_y += 120

img.save(OUTPUT)
print(f"Captura generada en {OUTPUT}")
