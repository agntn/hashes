import { ALGORITHMS, HMAC_COUNT } from "./utils/algorithms";
import { TOOLS } from "./utils/tools";
import { spellOut, spellOutCapital } from "./utils/format";

export default defineAppConfig({
  docus: {
    colorMode: "dark",
  },
  /** Landing JSON-LD: a free SoftwareApplication published by the agntn Organization, tied to GitHub and npm through sameAs. */
  seo: {
    title: "@agntn/hashes",
    description: `${spellOutCapital(ALGORITHMS.length)} hash algorithms behind one local API, a CLI and ${spellOut(TOOLS.length)} agent tools. SHA-2, SHA-3, BLAKE, Keccak-256, HASH160, scrypt. ${spellOutCapital(HMAC_COUNT)} with HMAC. All offline.`,
    schema: {
      type: "SoftwareApplication",
      applicationCategory: "DeveloperApplication",
      operatingSystem: "Node.js",
      price: 0,
      sameAs: ["https://github.com/agntn/hashes", "https://www.npmjs.com/package/@agntn/hashes"],
      organization: {
        name: "agntn",
        url: "https://agntn.dev",
        logo: "https://agntn.dev/icon-512.png",
        sameAs: ["https://github.com/agntn", "https://www.npmjs.com/org/agntn"],
      },
    },
  },
  header: {
    title: "@agntn/hashes",
  },
  /** Sections as tabs under the header, so the sidebar holds one section as the lists grow. */
  navigation: {
    sub: "header",
  },
  github: {
    url: "https://github.com/agntn/hashes",
    branch: "main",
    rootDir: "docs",
  },
  /** Docus adds the repository link itself, a GitHub social next to it is the same icon twice. */
  socials: {
    npm: "https://www.npmjs.com/package/@agntn/hashes",
  },
  ui: {
    colors: {
      primary: "amber",
      neutral: "slate",
    },
    /**
     * Buttons in the instrument grammar, by variant, so a page writes <UButton> and gets the look
     * from app.css: primary solid and neutral outline are boxed actions with the glyph in its own
     * cell, neutral subtle the small control of an instrument (`square` for a step button), and
     * the site's own `chip` variant a chip, primary for the picked one. Docus renders its search
     * field as neutral soft and its own buttons as neutral ghost and link, so those stay default.
     */
    button: {
      slots: {
        base: "h-9 rounded-lg px-3.5 text-sm leading-none font-medium cursor-pointer transition-colors",
      },
      variants: {
        variant: {
          chip: "",
        },
      },
      compoundVariants: [
        {
          color: "primary",
          variant: "solid",
          class: "hashes-action hashes-action-primary ring-0",
        },
        {
          color: "neutral",
          variant: "outline",
          class: "hashes-action ring-0",
        },
        {
          color: "neutral",
          variant: "subtle",
          class: "hashes-control ring-0",
        },
        {
          color: "neutral",
          variant: "subtle",
          square: true,
          class: "hashes-control-square",
        },
        {
          color: "neutral",
          variant: "chip",
          class: "hashes-chip",
        },
        {
          color: "primary",
          variant: "chip",
          class: "hashes-chip hashes-chip-on",
        },
      ],
    },
    /** Status words as boxed mono capitals: neutral quiet, subtle bright, primary the accent, error red. */
    badge: {
      slots: {
        base: "hashes-badge",
      },
      compoundVariants: [
        { color: "neutral", variant: "subtle", class: "hashes-badge-bright ring-0" },
        { color: "neutral", variant: "outline", class: "ring-0" },
        { color: "primary", variant: "outline", class: "hashes-badge-accent ring-0" },
        { color: "error", variant: "outline", class: "hashes-badge-error ring-0" },
      ],
    },
    /** Tabs as mono capitals on a quiet rule, the active one over an accent segment. */
    tabs: {
      compoundVariants: [
        {
          variant: "link",
          class: {
            list: "hashes-tabs-list",
            trigger: "hashes-tabs-trigger",
            indicator: "hashes-tabs-indicator",
          },
        },
      ],
    },
    /** A field with variant none sits inside a readout row: the row is its frame, the value is mono. */
    input: {
      compoundVariants: [
        { variant: "none", class: { base: "hashes-field", leadingIcon: "hashes-field-icon" } },
      ],
    },
    textarea: {
      compoundVariants: [{ variant: "none", class: { base: "hashes-field" } }],
    },
    selectMenu: {
      slots: {
        content: "hashes-menu rounded-none ring-0 shadow-none bg-transparent",
        group: "hashes-menu-group",
        item: "hashes-menu-item",
        itemLeadingIcon: "hashes-field-icon",
        input: "hashes-menu-input",
      },
      compoundVariants: [
        {
          variant: "none",
          class: {
            base: "hashes-field",
            leadingIcon: "hashes-field-icon",
            trailingIcon: "hashes-field-icon",
          },
        },
      ],
    },
    /** A failed read: a red edge and the message in mono, no box. */
    alert: {
      compoundVariants: [
        {
          color: "error",
          variant: "outline",
          class: {
            root: "hashes-alert ring-0",
            title: "hashes-alert-title",
            icon: "hashes-alert-icon",
          },
        },
      ],
    },
    /** A tooltip is a console label: flat, clipped corner, mono, and it wraps, because it carries full addresses. */
    tooltip: {
      slots: {
        content:
          "hashes-tooltip h-auto max-w-[min(32rem,calc(100vw-2rem))] rounded-none bg-transparent shadow-none ring-0 px-3 py-1.5 data-[state=delayed-open]:animate-none data-[state=closed]:animate-none",
        text: "whitespace-normal text-highlighted [overflow-wrap:anywhere]",
      },
    },
    /** The site header, the search field and the keys in the instrument grammar; the look lives in app.css. */
    header: {
      slots: {
        root: "hashes-site-header",
      },
    },
    contentSearchButton: {
      slots: {
        base: "hashes-search",
      },
    },
    /** The search modal and its palette in the instrument grammar; the look lives in app.css (portalled). */
    contentSearch: {
      slots: {
        modal: "hashes-search-modal",
      },
    },
    commandPalette: {
      slots: {
        root: "hashes-palette",
        input: "hashes-palette-input",
        close: "hashes-palette-close",
        group: "hashes-palette-group",
        label: "hashes-palette-label",
        item: "hashes-palette-item",
        itemLeadingIcon: "hashes-palette-icon",
        itemLabel: "hashes-palette-text",
        itemLabelBase: "hashes-palette-name",
        itemDescription: "hashes-palette-about",
        empty: "hashes-palette-empty",
      },
    },
    kbd: {
      base: "hashes-kbd",
    },
    pageHeader: {
      slots: {
        root: "hashes-page-header py-8 border-b-0",
        headline: "hashes-eyebrow mb-3",
        title: "text-3xl sm:text-4xl font-medium tracking-tight text-highlighted",
        description: "text-base leading-7 text-muted",
      },
    },
    /**
     * The layouts with a right aside get one track per panel instead of the ten column grid: the toc
     * takes a fixed 13.75rem, a little wider than Nuxt UI's, and the text keeps 52rem on a large
     * screen, the width the rosters need before they stack.
     */
    page: {
      compoundVariants: [
        {
          left: true,
          right: true,
          class: {
            root: "lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)_min(13.75rem,20%)]",
            left: "lg:col-span-1",
            center: "lg:col-span-1",
            right: "lg:col-span-1",
          },
        },
        {
          left: false,
          right: true,
          class: {
            root: "lg:grid-cols-[minmax(0,1fr)_min(13.75rem,20%)]",
            center: "lg:col-span-1",
            right: "lg:col-span-1",
          },
        },
      ],
    },
    /** Nuxt UI truncates TOC entries; headings here are sentences, so let them wrap. */
    contentToc: {
      slots: {
        linkText: "whitespace-normal",
      },
    },
    prose: {
      callout: {
        slots: {
          base: "rounded-xl px-4 py-3.5",
        },
      },
      card: {
        slots: {
          base: "rounded-xl hashes-frame border-0 p-5 bg-default hover:bg-muted",
          icon: "size-5 mb-3 text-muted transition-colors group-hover:text-primary",
          title: "text-sm font-medium",
          description: "text-sm text-muted",
        },
      },
      cardGroup: {
        base: "grid grid-cols-1 sm:grid-cols-2 gap-3 my-5 *:my-0",
      },
      /** Inline code in the instrument grammar; the look lives in `.hashes-code` in app.css. */
      code: {
        base: "hashes-code",
      },
      pre: {
        slots: {
          header: "border-default bg-default",
          base: "border-default bg-muted",
        },
      },
    },
    pageHero: {
      slots: {
        title: "font-medium tracking-tight",
        description: "text-base leading-7 sm:text-lg",
      },
    },
  },
});
