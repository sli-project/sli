declare module "node:child_process" {
  export function execFileSync(file: string, args: string[], options: { cwd: string; encoding: "utf8"; timeout?: number }): string;
}

declare module "node:path" {
  export function dirname(path: string): string;
  export function join(...paths: string[]): string;
  export function resolve(...paths: string[]): string;
}

interface ImportMeta {
  readonly dirname: string;
}

declare module "node:process" {
  const process: { env: Record<string, string | undefined>; platform: string };
  export default process;
}
