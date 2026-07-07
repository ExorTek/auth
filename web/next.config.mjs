import nextra from 'nextra';

const withNextra = nextra({
  defaultShowCopyCode: true,
  search: {
    codeblocks: false,
  },
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
