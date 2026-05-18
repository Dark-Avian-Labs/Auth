export function isSafeRelativePath(next: string): boolean {
  if (next.includes('\\') || /%5c/i.test(next)) {
    return false;
  }
  let decodedNext = next;
  for (let i = 0; i < 3; i++) {
    try {
      const candidate = decodeURIComponent(decodedNext);
      if (candidate === decodedNext) break;
      decodedNext = candidate;
    } catch {
      break;
    }
  }
  if (decodedNext.includes('\\') || decodedNext.includes('//')) {
    return false;
  }
  return decodedNext.startsWith('/') && !/^[a-zA-Z][a-zA-Z\d+\-.]*:/.test(decodedNext);
}
