import { useMDXComponents as getDocsMDXComponents } from 'nextra-theme-docs';

export function useMDXComponents(components) {
  const docs = getDocsMDXComponents();
  return { ...docs, ...components };
}
