export default {
  test: {
    css: {
      // Keep raw CSS contract imports intact when Vitest runs from the repository root.
      include: [/\/design-system\/ds\.css\?raw(?:&.*)?$/],
    },
  },
};
