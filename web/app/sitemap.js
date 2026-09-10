import { getPageMap } from 'nextra/page-map';

const SITE_URL = 'https://auth.memet.dev';

// Walk the Nextra page map and collect every routable page. Deriving the
// sitemap from the page map (rather than a hand-kept list) keeps it correct as
// packages and pages are added — the previous static ROUTES array had already
// drifted several sections behind the content tree.
const collectRoutes = (nodes, out = new Set()) => {
  for (const node of nodes ?? []) {
    if (typeof node.route === 'string' && !node.route.includes('[')) {
      out.add(node.route);
    }
    if (Array.isArray(node.children)) {
      collectRoutes(node.children, out);
    }
  }
  return out;
};

// Deeper pages get a lower priority; the home page ranks highest, package roots
// above their sub-pages.
const priorityFor = route => {
  if (route === '/') return 1;
  const depth = route.split('/').filter(Boolean).length;
  return depth <= 1 ? 0.8 : 0.6;
};

export default async function sitemap() {
  const pageMap = await getPageMap();
  const routes = [...collectRoutes(pageMap)].sort();
  const lastModified = new Date();

  return routes.map(route => ({
    url: route === '/' ? SITE_URL : `${SITE_URL}${route}`,
    lastModified,
    changeFrequency: 'weekly',
    priority: priorityFor(route),
  }));
}
