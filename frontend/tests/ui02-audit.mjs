import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

// A repeatable source inventory, not a CSS parser or a visual acceptance gate.
const source = fileURLToPath(new URL('../src/', import.meta.url));
const files = [];
function visit(directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const name = path.join(directory, entry.name);
    if (entry.isDirectory()) visit(name);
    else if (/\.(css|tsx?)$/.test(name) && !/\.(test|spec)\./.test(name)) files.push(name);
  }
}
visit(source);
function selectors(value) {
  const result = [];
  let depth = 0, start = 0;
  for (let index = 0; index < value.length; index++) {
    if ('(['.includes(value[index])) depth++;
    else if (')]'.includes(value[index])) depth--;
    else if (value[index] === ',' && depth === 0) { result.push(value.slice(start, index)); start = index + 1; }
  }
  return [...result, value.slice(start)];
}
const rows = files.sort().map(file => {
  const content = process.argv.includes('--baseline')
    ? execFileSync('git', ['show', `HEAD:frontend/src/${path.relative(source, file).replaceAll('\\', '/')}`], { encoding: 'utf8' })
    : readFileSync(file, 'utf8');
  const text = content.replace(/\/\*[\s\S]*?\*\//g, '');
  const row = { file: path.relative(source, file).replaceAll('\\', '/'), colors: 0, dimensions: 0, unscopedSelectors: 0, inlineStyles: 0, inlineButtons: 0 };
  if (file.endsWith('.css') && !file.endsWith('tokens.css')) {
    for (const rule of text.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
      for (const selector of selectors(rule[1])) {
        if (!selector.includes('.sli-') && !selector.includes('#root') && !/^\s*(@|from\b|to\b|\d+%)/.test(selector)) row.unscopedSelectors++;
      }
      for (const declaration of rule[2].split(';')) {
        const colon = declaration.indexOf(':');
        if (colon < 0 || declaration.trimStart().startsWith('--')) continue;
        // Token fallbacks count as literals too: their drift remains visible.
        const value = declaration.slice(colon + 1);
        if (/#(?:[\da-f]{3,8})\b|\b(?:rgba?|hsla?)\(/i.test(value)) row.colors++;
        if (/(?:\d|\.)\d*(?:px|rem|em|pt|ch)\b/.test(value)) row.dimensions++;
      }
    }
  } else if (/\.tsx?$/.test(file)) {
    row.colors = [...text.matchAll(/["'`]#[\da-f]{3,8}["'`]|["'`](?:rgba?|hsla?)\(/gi)].length;
    row.inlineStyles = [...text.matchAll(/\bstyle=\{\{/g)].length;
    row.inlineButtons = [...text.matchAll(/<button\b[^>]*className="sli-ds-button(?:\s|"|$)/g)].length;
  }
  return row;
});
const count = subset => subset.reduce((sum, row) => {
  for (const key of Object.keys(sum)) sum[key] += row[key];
  return sum;
}, { colors: 0, dimensions: 0, unscopedSelectors: 0, inlineStyles: 0, inlineButtons: 0 });
console.log(JSON.stringify({ scope: 'src CSS/TS/TSX; tests and token definitions excluded; declaration counts, inline style/button candidates',
  totals: count(rows), production: count(rows.filter(row => !row.file.startsWith('sli-v4/'))), historical: count(rows.filter(row => row.file.startsWith('sli-v4/'))),
  files: rows.filter(row => Object.values(row).slice(1).some(Boolean)) }, null, 2));
