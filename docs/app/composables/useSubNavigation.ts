import type { ContentNavigationItem } from "@nuxt/content";
import { ALGORITHMS } from "../utils/algorithms";

const NAV_ICONS: Record<string, string> = {
  "/guide": "i-lucide-book-open",
  "/guide/hashing": "i-lucide-hash",
  "/guide/verify": "i-lucide-check-check",
  "/guide/kdf": "i-lucide-hourglass",
  "/guide/extend": "i-lucide-arrow-right-to-line",
  "/guide/identify": "i-lucide-scan-search",
  "/guide/cli": "i-lucide-terminal",
  "/guide/agents": "i-lucide-bot",
  "/guide/custom": "i-lucide-plus",
  "/guide/playground": "i-lucide-flask-conical",
  "/algorithms": "i-lucide-library",
  "/playground": "i-lucide-flask-conical",
  ...Object.fromEntries(ALGORITHMS.map((algorithm) => [algorithm.to, algorithm.icon])),
};

function withIcons(items: readonly ContentNavigationItem[]): ContentNavigationItem[] {
  return items.map((item) => ({
    ...item,
    icon: NAV_ICONS[item.path] ?? item.icon,
    /** Leaf pages match exactly, so /guide isn't highlighted together with /guide/cli. */
    exact: !item.children?.length,
    children: item.children ? withIcons(item.children) : item.children,
  }));
}

/**
 * The first page under a section, which is where its tab in the header leads.
 *
 * @param {ContentNavigationItem} item - A section of the tree.
 * @returns {string} The path of its first page.
 */
function firstPagePath(item: ContentNavigationItem): string {
  let current = item;
  while (current.children?.length) current = current.children[0]!;
  return current.path;
}

/**
 * Whether the route is inside a section: on one of its pages, or under its path.
 *
 * @param {ContentNavigationItem} section - A section of the tree.
 * @param {string} path - The route path.
 * @returns {boolean} Whether the section owns the page.
 */
function owns(section: ContentNavigationItem, path: string): boolean {
  return (
    path === section.path ||
    path.startsWith(`${section.path}/`) ||
    (section.children ?? []).some((page) => page.path === path && !("lead" in page && page.lead))
  );
}

/**
 * The navigation with this site's icons. With sub-navigation in the header the sidebar holds the
 * current section only, title included; `sections` feeds the header's tabs and `fullNavigation` the
 * mobile menu, which has no tabs and needs every section.
 *
 * @returns {object} `sidebarNavigation`, `fullNavigation` and `sections`.
 */
export function useSubNavigation() {
  const route = useRoute();
  const appConfig = useAppConfig();
  const navigation = inject<Ref<ContentNavigationItem[]>>("navigation");

  const subNavigationMode = computed(() =>
    route.meta.layout === "docs"
      ? (appConfig.navigation as { sub?: "header" | "aside" } | undefined)?.sub
      : undefined,
  );

  const fullNavigation = computed(() => withIcons(navigation?.value ?? []));

  const currentSection = computed(() => {
    if (!subNavigationMode.value) return undefined;
    const path = route.path.replace(/\/$/, "") || "/";
    return (
      fullNavigation.value.find((section) => owns(section, path)) ??
      fullNavigation.value.find((section) =>
        (section.children ?? []).some((page) => page.path === path),
      )
    );
  });

  const sidebarNavigation = computed(() =>
    subNavigationMode.value === "header" && currentSection.value
      ? [currentSection.value]
      : fullNavigation.value,
  );

  const sections = computed(() => {
    const path = route.path.replace(/\/$/, "") || "/";
    return fullNavigation.value.map((item) => ({
      title: item.title,
      icon: item.icon,
      to: item.path === "/guide" ? firstPagePath(item) : item.path,
      active: owns(item, path),
    }));
  });

  return { sidebarNavigation, fullNavigation, sections };
}
