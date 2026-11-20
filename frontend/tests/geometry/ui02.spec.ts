import { expect, test, type Locator, type Page } from '@playwright/test';
import { installFixtures, longError, longLabel, screens } from './ui02-fixtures';

async function noPageOverflow(page: Page) {
  const widths = await page.evaluate(() => [document.documentElement, document.body, document.getElementById('root')!].map(element => ({
    name: element.id || element.tagName, client: element.clientWidth, scroll: element.scrollWidth,
  })));
  for (const width of widths) expect(width.scroll, `${width.name}: horizontal page overflow`).toBeLessThanOrEqual(width.client + 1);
}

async function usableActions(actions: Locator) {
  let checked = 0;
  for (const action of await actions.all()) {
    if (!await action.isVisible()) continue;
    checked++;
    await action.scrollIntoViewIfNeeded();
    const measurement = await action.evaluate(element => {
      const rect = element.getBoundingClientRect();
      let left = 0, right = innerWidth, top = 0, bottom = innerHeight;
      for (let parent = element.parentElement; parent; parent = parent.parentElement) {
        const style = getComputedStyle(parent);
        const bounds = parent.getBoundingClientRect();
        if (/auto|scroll|hidden|clip/.test(style.overflowX)) { left = Math.max(left, bounds.left); right = Math.min(right, bounds.right); }
        if (/auto|scroll|hidden|clip/.test(style.overflowY)) { top = Math.max(top, bounds.top); bottom = Math.min(bottom, bounds.bottom); }
      }
      const hit = document.elementFromPoint((rect.left + rect.right) / 2, (rect.top + rect.bottom) / 2);
      return {
        label: element.textContent, width: rect.width, height: rect.height,
        inside: rect.left >= left - 1 && rect.right <= right + 1 && rect.top >= top - 1 && rect.bottom <= bottom + 1,
        hit: Boolean(hit && (element.contains(hit) || hit === element)),
        clippedText: element.scrollWidth > element.clientWidth + 1 || element.scrollHeight > element.clientHeight + 1,
      };
    });
    expect(measurement.width, measurement.label || 'action').toBeGreaterThan(0);
    expect(measurement.height).toBeGreaterThan(0);
    expect(measurement.inside, `clipped action: ${measurement.label}`).toBe(true);
    expect(measurement.hit, `covered action: ${measurement.label}`).toBe(true);
    expect(measurement.clippedText, `clipped label: ${measurement.label}`).toBe(false);
  }
  expect(checked, 'must exercise real primary actions').toBeGreaterThan(0);
}

async function visibleKeyboardFocus(page: Page, dialog = false) {
  const focus = await page.evaluate(() => {
    const element = document.activeElement as HTMLElement;
    const style = getComputedStyle(element);
    const search = element.closest('.sli-ds-shell__search');
    const indicator = search ? getComputedStyle(search) : style;
    const rect = element.getBoundingClientRect();
    const hit = document.elementFromPoint((rect.left + rect.right) / 2, (rect.top + rect.bottom) / 2);
    return {
      inDialog: Boolean(element.closest('[role="dialog"]')),
      visible: element.matches(':focus-visible') && rect.width > 0 && rect.height > 0,
      indicator: indicator.outlineStyle !== 'none' && parseFloat(indicator.outlineWidth) > 0 && indicator.outlineColor !== 'transparent' && indicator.outlineColor !== 'rgba(0, 0, 0, 0)',
      reachable: rect.left >= -1 && rect.right <= innerWidth + 1 && rect.top >= -1 && rect.bottom <= innerHeight + 1,
      hit: Boolean(hit && element.contains(hit)),
    };
  });
  expect(focus.visible, 'keyboard focus visible').toBe(true);
  expect(focus.indicator, 'keyboard focus has an outline').toBe(true);
  expect(focus.reachable, 'focused action stays in the viewport').toBe(true);
  expect(focus.hit, 'focused action is not covered').toBe(true);
  if (dialog) expect(focus.inDialog, 'drawer traps focus').toBe(true);
}

async function expandFilters(page: Page) {
  const toggle = page.locator('.sli-ds-filters__toggle');
  if (await toggle.isVisible() && await toggle.getAttribute('aria-expanded') === 'false') await toggle.click();
  for (const summary of await page.locator('.sli-ds-filters__additional:not([open]) > summary').all()) await summary.click();
}

for (const width of [390, 768, 1280, 1920]) for (const zoom of [1.25, 1.5]) for (const theme of ['light', 'dark']) {
  for (const screen of screens) {
    test(`${screen.name} ${width}px ${zoom * 100}% ${theme}`, async ({ browser }, testInfo) => {
      // Desktop browser zoom reduces the CSS viewport and increases DPR. Model
      // both, so media queries and fixed drawers reflow, unlike CSS zoom or a
      // deviceScaleFactor-only screenshot. Native browser-menu zoom is separate.
      const context = await browser.newContext({
        baseURL: 'http://127.0.0.1:4173', timezoneId: 'UTC',
        viewport: { width: Math.floor(width / zoom), height: Math.floor(900 / zoom) },
        screen: { width, height: 900 }, deviceScaleFactor: zoom,
        locale: 'ru-RU', colorScheme: theme as 'light' | 'dark', reducedMotion: 'reduce',
      });
      const page = await context.newPage();
      await context.tracing.start({ screenshots: true, snapshots: true });
      const { state, unexpected } = await installFixtures(page, theme);
      const errors: string[] = [];
      page.on('pageerror', error => errors.push(error.message));
      try {
        await page.goto(screen.path);
        await expect(page.locator(screen.ready).first()).toBeVisible();
        await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
        await expect(page.locator('h1')).toContainText(longLabel);
        await expandFilters(page);
        await noPageOverflow(page);
        await usableActions(page.locator('.sli-ds-header__actions .sli-ds-button, .sli-ds-filters__actions .sli-ds-button, .sli-ds-home-rows a'));
        // Start at the document, then exercise the actual shell and page order.
        await page.evaluate(() => { (document.activeElement as HTMLElement)?.blur(); window.scrollTo(0, 0); });
        for (let index = 0; index < 6; index++) { await page.keyboard.press('Tab'); await visibleKeyboardFocus(page); }

        if ('key' in screen) {
          const row = page.locator('.sli-ds-table tbody tr').first();
          await row.focus();
          await page.keyboard.press('Enter');
          const dialog = page.getByRole('dialog');
          await expect(dialog).toBeVisible();
          await noPageOverflow(page);
          await usableActions(dialog.locator('.sli-ds-drawer__header button, .sli-ds-drawer__footer .sli-ds-button'));
          // Initial reverse Tab and repeated forward traversal must stay inside.
          await dialog.focus();
          await page.keyboard.press('Shift+Tab');
          await visibleKeyboardFocus(page, true);
          for (let index = 0; index < 6; index++) { await page.keyboard.press('Tab'); await visibleKeyboardFocus(page, true); }
          const body = dialog.locator('.sli-ds-drawer__body');
          expect(await body.evaluate(element => element.scrollHeight > element.clientHeight), 'exercise scrolling in a populated drawer').toBe(true);
          await body.evaluate(element => { element.scrollTop = element.scrollHeight; });
          await expect(dialog.getByRole('button', { name: 'Закрыть', exact: true })).toBeInViewport();
          await page.keyboard.press('Escape');
          await expect(dialog).toHaveCount(0);
          await expect(row).toBeFocused();
        }

        state.error = true;
        await page.reload();
        await expect(page.getByText(longError, { exact: true }).first()).toBeVisible();
        await expandFilters(page);
        await noPageOverflow(page);
        await usableActions(page.locator('.sli-ds-state > .sli-ds-button, .sli-ds-state__actions button, .sli-ds-filters__actions button'));
        expect(unexpected, 'all API requests are synthetic and explicitly handled').toEqual([]);
        expect(errors, 'no page render errors').toEqual([]);
      } finally {
        try {
          await testInfo.attach('geometry.json', { body: Buffer.from(JSON.stringify({ width, zoom, theme, screen: screen.path, cssViewport: page.viewportSize() })), contentType: 'application/json' });
          if (testInfo.status !== testInfo.expectedStatus) {
            await testInfo.attach('failure.png', { body: await page.screenshot({ fullPage: true }), contentType: 'image/png' });
            const trace = testInfo.outputPath('trace.zip');
            await context.tracing.stop({ path: trace });
            await testInfo.attach('trace', { path: trace, contentType: 'application/zip' });
          } else await context.tracing.stop();
        } finally {
          await context.close();
        }
      }
    });
  }
}
