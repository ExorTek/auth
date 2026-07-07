import { Footer, Layout, Navbar } from 'nextra-theme-docs';
import { Head } from 'nextra/components';
import { getPageMap } from 'nextra/page-map';
import 'nextra-theme-docs/style.css';

export const metadata = {
  title: {
    default: '@exortek/auth',
    template: '%s — @exortek/auth',
  },
  description: 'Framework-agnostic, zero-dependency authentication primitives for Node.js.',
};

const navbar = <Navbar logo={<b>@exortek/auth</b>} projectLink="https://github.com/ExorTek/auth" />;
const footer = <Footer>MIT © {new Date().getFullYear()} · @exortek/auth</Footer>;

export default async function RootLayout({ children }) {
  return (
    <html lang="en" dir="ltr" suppressHydrationWarning>
      <Head />
      <body>
        <Layout
          navbar={navbar}
          footer={footer}
          pageMap={await getPageMap()}
          docsRepositoryBase="https://github.com/ExorTek/auth/tree/master/web"
        >
          {children}
        </Layout>
      </body>
    </html>
  );
}
