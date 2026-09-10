(() => {
  const menu = document.querySelector('.navbar__menu');
  if (!menu) return;

  const items = [...menu.querySelectorAll('.navbar__menu-item')];
  const desktop = window.matchMedia('(min-width: 1025px)');
  const compactWidth = 72;
  let start = 0;
  let initialized = false;

  function layout() {
    if (!desktop.matches) {
      menu.classList.remove('navbar__menu--compact');
      return;
    }

    // Medir os rótulos completos mesmo quando os links estão recolhidos.
    const widths = items.map(item => {
      const style = getComputedStyle(item);
      const label = item.querySelector('.navbar__item-label');
      return Math.max(compactWidth, Math.ceil(label.getBoundingClientRect().width
        + parseFloat(style.paddingLeft) + parseFloat(style.paddingRight)));
    });
    const gap = parseFloat(getComputedStyle(menu).columnGap) || 0;
    const available = menu.clientWidth;
    const allFit = widths.reduce((sum, width) => sum + width, 0)
      + gap * (items.length - 1) <= available;

    function expandedEnd(from) {
      // Reservar espaço para todos os links recolhidos.
      let remaining = available - compactWidth * items.length - gap * (items.length - 1);
      let end = from - 1;
      for (let index = from; index < items.length; index += 1) {
        const extra = widths[index] - compactWidth;
        if (extra > remaining) break;
        remaining -= extra;
        end = index;
      }
      return end;
    }

    if (!initialized) {
      const current = items.findIndex(item => item.getAttribute('aria-current') === 'page');
      if (!allFit && current > expandedEnd(0)) start = current;
      initialized = true;
    }

    if (allFit) start = 0;
    const end = allFit ? items.length - 1 : expandedEnd(start);
    items.forEach((item, index) => {
      const collapsed = !allFit && (index < start || index > end);
      item.style.setProperty('--nav-item-width', `${collapsed ? compactWidth : widths[index]}px`);
      item.classList.toggle('navbar__menu-item--collapsed', collapsed);
    });
    menu.classList.add('navbar__menu--compact');
  }

  items.forEach((item, index) => {
    item.addEventListener('click', event => {
      if (!desktop.matches || event.button !== 0
        || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;

      if (item.classList.contains('navbar__menu-item--collapsed')) {
        event.preventDefault();
        start = index;
        layout();
      }
    });

    // Tab revela o nome; o foco causado pelo mouse aguarda o clique para expandir.
    item.addEventListener('focus', () => {
      if (desktop.matches && item.matches(':focus-visible')
        && item.classList.contains('navbar__menu-item--collapsed')) {
        start = index;
        layout();
      }
    });
  });

  new ResizeObserver(layout).observe(menu);
  desktop.addEventListener('change', layout);
  document.fonts.ready.then(layout);
  layout();
})();
