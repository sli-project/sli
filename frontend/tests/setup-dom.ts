// React Aria uses CSS.escape for collection keys. jsdom 25 omits it.
if (typeof window !== "undefined" && !globalThis.CSS?.escape) {
  globalThis.CSS = {
    ...globalThis.CSS,
    escape: (value: string) =>
      Array.from(String(value), (character) => "\\" + (character.codePointAt(0) || 0xfffd).toString(16) + " ").join(""),
  };
}
