import nextra from 'nextra';

const withNextra = nextra({
  defaultShowCopyCode: true,
  // Pagefind (Nextra's default search) needs a post-build step to
  // generate the /_pagefind index. Disabled until we wire that.
  search: false,
  mdxOptions: {
    rehypePrettyCodeOptions: {
      theme: {
        light: 'one-light',
        dark: 'one-dark-pro',
      },
    },
  },
});

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
};

export default withNextra(nextConfig);
