// A line diff for the "what changes" view: the longest common subsequence,
// which for manifests of a few hundred lines is instant.
export type DiffLine = { kind: "same" | "add" | "del"; text: string };

export function diffLines(before: string, after: string): DiffLine[] {
  const a = before.split("\n");
  const b = after.split("\n");
  const n = a.length;
  const m = b.length;
  const lcs: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
    }
  }
  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      out.push({ kind: "same", text: a[i] });
      i++;
      j++;
    } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
      out.push({ kind: "del", text: a[i++] });
    } else {
      out.push({ kind: "add", text: b[j++] });
    }
  }
  while (i < n) out.push({ kind: "del", text: a[i++] });
  while (j < m) out.push({ kind: "add", text: b[j++] });
  return out;
}

/// The server fills in what nobody wrote (status, uid, timestamps): leaving
/// those lines out keeps a diff about what a person changed.
export function withoutNoise(yaml: string): string {
  const out: string[] = [];
  let skip = -1;
  for (const line of yaml.split("\n")) {
    const indent = line.length - line.trimStart().length;
    if (skip >= 0 && (indent > skip || line.trim() === "")) continue;
    skip = -1;
    const key = line.trim().split(":")[0];
    if ((indent === 0 && key === "status") || (indent === 2 && ["uid", "resourceVersion", "generation", "creationTimestamp"].includes(key))) {
      skip = indent;
      continue;
    }
    out.push(line);
  }
  return out.join("\n");
}
