import { generateStaticParamsFor, importPage } from 'nextra/pages';
import { useMDXComponents as getMDXComponents } from '../../mdx-components.jsx';

export const generateStaticParams = generateStaticParamsFor('mdxPath');

export async function generateMetadata(props) {
  const params = await props.params;
  const { metadata } = await importPage(params.mdxPath);

  // Per-page canonical. The root layout declares alternates.canonical: '/',
  // which every page would otherwise inherit — pointing all sub-pages'
  // canonical at the homepage and telling search engines to treat them as
  // duplicates. Resolve it to this page's own path instead.
  const pathname = Array.isArray(params.mdxPath) && params.mdxPath.length ? `/${params.mdxPath.join('/')}` : '/';

  // Point the page's OG/Twitter card at the dynamic /og endpoint, seeded with
  // this page's own title and description so every share card is specific.
  const title = typeof metadata?.title === 'string' ? metadata.title : '@exortek/auth';
  const heading = title.replace(/\s+[—-]\s+Overview$/i, '').trim();
  const desc = typeof metadata?.description === 'string' ? metadata.description : '';
  const ogUrl = `/og?title=${encodeURIComponent(heading)}${desc ? `&desc=${encodeURIComponent(desc)}` : ''}`;

  return {
    ...metadata,
    alternates: { ...metadata?.alternates, canonical: pathname },
    // Re-declare the stable OG fields: setting openGraph here replaces the
    // layout's object wholesale, so siteName/type/locale would be lost.
    openGraph: {
      type: 'website',
      siteName: '@exortek/auth',
      locale: 'en_US',
      ...metadata?.openGraph,
      url: pathname,
      images: [{ url: ogUrl, width: 1200, height: 630 }],
    },
    twitter: { card: 'summary_large_image', ...metadata?.twitter, images: [ogUrl] },
  };
}

const Wrapper = getMDXComponents().wrapper;

export default async function Page(props) {
  const params = await props.params;
  const result = await importPage(params.mdxPath);
  const { default: MDXContent, toc, metadata, sourceCode } = result;
  return (
    <Wrapper toc={toc} metadata={metadata} sourceCode={sourceCode}>
      <MDXContent {...props} params={params} />
    </Wrapper>
  );
}
