import Link from 'next/link';

const DOCS_ISSUE = 'https://github.com/ExorTek/auth/issues/new?template=documentation.yml';

export default function NotFound() {
  return (
    <div style={{ textAlign: 'center', maxWidth: '40rem', margin: '4rem auto', padding: '0 1.5rem' }}>
      <div className="home-eyebrow" style={{ fontSize: '3rem', letterSpacing: '-0.02em' }}>
        404
      </div>
      <h1 className="home-title" style={{ maxWidth: 'none', margin: '0.25rem 0 1rem' }}>
        This page slipped through.
      </h1>
      <div className="home-sub" style={{ margin: '0 auto 1.75rem' }}>
        The page you're after doesn't exist or has moved. Here's the way back in:
      </div>
      <div className="home-cta" style={{ justifyContent: 'center' }}>
        <Link className="home-btn home-btn-primary" href="/">
          Home
        </Link>
        <Link className="home-btn home-btn-ghost" href="/guides">
          Guides
        </Link>
        <Link className="home-btn home-btn-ghost" href="/comparison">
          Comparison
        </Link>
      </div>
      <div style={{ marginTop: '2rem', fontSize: '0.875rem', opacity: 0.75 }}>
        Landed here from a link on the site?{' '}
        <a href={DOCS_ISSUE} style={{ color: '#12b76a', fontWeight: 600 }}>
          Report the broken link →
        </a>
      </div>
    </div>
  );
}
