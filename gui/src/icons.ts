import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
/// Site icons.
///
/// They come from the icon service of the same server the vault is on: in
/// Vaultwarden that is `/icons/{domain}/icon.png`, in Bitwarden's cloud a
/// separate host. Going to a third party for pictures is not allowed: it would
/// reveal the list of sites somebody has passwords for to a party that does not
/// hold the vault.

const CLOUD = "https://icons.bitwarden.net";

export function iconsBase(baseUrl: string): string {
  const url = baseUrl.trim().replace(/\/$/, "");
  if (!url) return "";
  if (url.endsWith("vault.bitwarden.com") || url.endsWith("vault.bitwarden.eu")) return CLOUD;
  return `${url}/icons`;
}

/// The domain out of an item's address. Items hold anything at all, from
/// `example.com` to `https://example.com/login?next=/`, so the parsing is
/// forgiving.
export function domainOf(uri: string): string | null {
  const raw = uri.trim();
  if (!raw) return null;
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`;
  try {
    const host = new URL(withScheme).hostname.replace(/^www\./, "");
    return host.includes(".") ? host : null;
  } catch {
    return null;
  }
}

/// A site icon through the daemon: it throws Vaultwarden's placeholder away
/// itself.
/// `undefined` means we do not know yet, `null` that there is no icon, a
/// string is a data URL.
const memo = new Map<string, string | null>();
const pending = new Map<string, Promise<string | null>>();

export function siteIconDomain(baseUrl: string, uris: string[]): string | null {
  if (!iconsBase(baseUrl)) return null;
  for (const uri of uris) {
    const domain = domainOf(uri);
    if (domain) return domain;
  }
  return null;
}

export function useSiteIcon(baseUrl: string, uris: string[], enabled = true): string | null | undefined {
  const domain = enabled ? siteIconDomain(baseUrl, uris) : null;
  const [icon, setIcon] = useState<string | null | undefined>(() => (domain ? memo.get(domain) : null));
  useEffect(() => {
    if (!domain) {
      setIcon(null);
      return;
    }
    if (memo.has(domain)) {
      setIcon(memo.get(domain) ?? null);
      return;
    }
    let alive = true;
    setIcon(undefined);
    let p = pending.get(domain);
    if (!p) {
      p = invoke<string | null>("site_icon", { domain })
        .catch(() => null)
        .then((v) => {
          memo.set(domain, v);
          pending.delete(domain);
          return v;
        });
      pending.set(domain, p);
    }
    void p.then((v) => {
      if (alive) setIcon(v);
    });
    return () => {
      alive = false;
    };
  }, [domain]);
  return icon;
}

/// A picture's dominant hue: the average colour of its saturated opaque
/// pixels. Grey and nearly transparent ones do not count, or any icon on a
/// white ground would give a colour of nothing. When there is little saturation,
/// there is no hue.
const hueMemo = new Map<string, number | null>();

function hueOfImage(img: HTMLImageElement): number | null {
  const size = 24;
  const canvas = document.createElement("canvas");
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  if (!ctx) return null;
  try {
    ctx.drawImage(img, 0, 0, size, size);
    const { data } = ctx.getImageData(0, 0, size, size);
    let x = 0;
    let y = 0;
    let n = 0;
    for (let i = 0; i < data.length; i += 4) {
      const r = data[i] / 255;
      const g = data[i + 1] / 255;
      const b = data[i + 2] / 255;
      const a = data[i + 3] / 255;
      if (a < 0.5) continue;
      const max = Math.max(r, g, b);
      const min = Math.min(r, g, b);
      const l = (max + min) / 2;
      const s = max === min ? 0 : (max - min) / (1 - Math.abs(2 * l - 1));
      if (s < 0.25 || l < 0.12 || l > 0.92) continue;
      let h = 0;
      if (max === r) h = ((g - b) / (max - min)) % 6;
      else if (max === g) h = (b - r) / (max - min) + 2;
      else h = (r - g) / (max - min) + 4;
      const rad = (h * 60 * Math.PI) / 180;
      // Weighted by saturation: a bright patch matters more than a pale
      // ground.
      x += Math.cos(rad) * s;
      y += Math.sin(rad) * s;
      n += 1;
    }
    if (n < 8) return null;
    const deg = (Math.atan2(y, x) * 180) / Math.PI;
    return Math.round((deg + 360) % 360);
  } catch {
    return null;
  }
}

export function useImageHue(src: string | null): number | null {
  const [hue, setHue] = useState<number | null>(() => (src ? hueMemo.get(src) ?? null : null));
  useEffect(() => {
    if (!src) {
      setHue(null);
      return;
    }
    if (hueMemo.has(src)) {
      setHue(hueMemo.get(src) ?? null);
      return;
    }
    let alive = true;
    const img = new Image();
    img.onload = () => {
      const h = hueOfImage(img);
      hueMemo.set(src, h);
      if (alive) setHue(h);
    };
    img.onerror = () => {
      hueMemo.set(src, null);
      if (alive) setHue(null);
    };
    img.src = src;
    return () => {
      alive = false;
    };
  }, [src]);
  return hue;
}

export function faviconUrl(baseUrl: string, uris: string[]): string | null {
  const base = iconsBase(baseUrl);
  if (!base) return null;
  for (const uri of uris) {
    const domain = domainOf(uri);
    if (domain) return `${base}/${domain}/icon.png`;
  }
  return null;
}
