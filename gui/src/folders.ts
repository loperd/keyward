/// A folder's colour.
///
/// The same icon on every folder does not help: in a list of a dozen names the
/// eye reads the text anyway. A steady hue derived from the name gives a folder
/// a face — and the same hue works as a hint in the common list, where it is
/// otherwise unclear where an item came from. The saturation and the lightness
/// are fixed so that the palette does not fall apart into a parrot's.
export function folderHue(name: string): number {
  let h = 0;
  for (const ch of name) {
    h = (h * 31 + ch.codePointAt(0)!) % 360;
  }
  // The blue range belongs to the application's accent; folders do not take
  // it.
  const reserved = h >= 205 && h <= 245;
  return reserved ? (h + 60) % 360 : h;
}

export function folderColor(name: string): string {
  return `hsl(${folderHue(name)} 52% 62%)`;
}
